// Package report builds per-case handover summaries from a ledger directory.
//
// It offers two paths that share one parsed index:
//
//   - Full       recomputes every case (reads each committed version's actual
//     attachment bytes in both packs, re-verifies the two-root approval set, and
//     re-checks the version chain);
//   - Incremental recomputes only an explicit set of affected cases and skips the
//     rest entirely.
//
// Because the per-case recompute is the expensive unit, the incremental path is
// the "recompute only the relevant dossiers" behaviour the task asks for.  The
// two paths must agree byte-for-byte on the affected cases.
package report

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"handover/internal/model"
)

// CaseSummary is the recomputed state of one case.
type CaseSummary struct {
	Case           model.CaseID     `json:"case"`
	HighestVersion uint64           `json:"highest_version"`
	Digest         model.Digest     `json:"digest"`
	FromTenant     model.TenantID   `json:"from_tenant"`
	ToTenant       model.TenantID   `json:"to_tenant"`
	AuthGen        uint64           `json:"auth_gen"`
	CommittedSeq   uint64           `json:"committed_seq"`
	Versions       []VersionSummary `json:"versions"`
	Attempts       int              `json:"attempts"`
	Problems       []string         `json:"problems,omitempty"`
	Health         string           `json:"health"`
}

// VersionSummary is one committed version.
type VersionSummary struct {
	Version      uint64       `json:"version"`
	Digest       model.Digest `json:"digest"`
	CommittedSeq uint64       `json:"committed_seq"`
}

// Report is a set of case summaries plus bookkeeping.
type Report struct {
	Cases map[model.CaseID]*CaseSummary `json:"cases"`
	// CaseRecomputes counts how many cases this report actually recomputed.
	CaseRecomputes int `json:"case_recomputes"`
	// CasesConsidered counts cases the scope asked about (all, or affected).
	CasesConsidered int `json:"cases_considered"`
}

// Summary renders a one-line description.
func (r *Report) Summary() string {
	return fmt.Sprintf("cases=%d recomputes=%d", len(r.Cases), r.CaseRecomputes)
}

// Index is the parsed, reusable view of a ledger directory.
type Index struct {
	dir     string
	keyring *model.Keyring

	// byCase groups committed accepts by case, in journal order.
	byCase map[model.CaseID][]committed
	// attemptsByCase counts audited attempts naming each case.
	attemptsByCase map[model.CaseID]int
	// allCases is the sorted set of committed cases.
	allCases []model.CaseID

	packs packSet
}

type committed struct {
	seq uint64
	acc model.AcceptPayload
}

// BuildIndex parses the ledger once.
func BuildIndex(dir string, keyring *model.Keyring) (*Index, error) {
	ix := &Index{
		dir:            dir,
		keyring:        keyring,
		byCase:         make(map[model.CaseID][]committed),
		attemptsByCase: make(map[model.CaseID]int),
	}
	journal, err := parseLog(filepath.Join(dir, "journal.jsonl"), model.JournalDomain)
	if err != nil {
		return nil, err
	}
	for _, rec := range journal {
		if rec.Type != model.TypeAccept {
			continue
		}
		var a model.AcceptPayload
		if err := json.Unmarshal(rec.Payload, &a); err != nil {
			return nil, err
		}
		ix.byCase[a.Case] = append(ix.byCase[a.Case], committed{seq: rec.Seq, acc: a})
	}
	recon, err := parseLog(filepath.Join(dir, "reconciled.jsonl"), model.ReconDomain)
	if err != nil {
		return nil, err
	}
	for _, rec := range recon {
		if rec.Type != model.ReconAttempt {
			continue
		}
		var at model.AttemptPayload
		if err := json.Unmarshal(rec.Payload, &at); err != nil {
			return nil, err
		}
		ix.attemptsByCase[at.Case]++
	}
	for c := range ix.byCase {
		ix.allCases = append(ix.allCases, c)
	}
	sort.Slice(ix.allCases, func(i, j int) bool { return ix.allCases[i] < ix.allCases[j] })
	packs, err := openPacks(dir)
	if err != nil {
		return nil, err
	}
	ix.packs = packs
	return ix, nil
}

// AllCases returns the committed cases in sorted order.
func (ix *Index) AllCases() []model.CaseID { return append([]model.CaseID(nil), ix.allCases...) }

// Full recomputes every case.
func (ix *Index) Full() (*Report, error) {
	return ix.build(ix.allCases)
}

// Incremental recomputes only the affected cases.  It returns the report and the
// cases it skipped, which must be the complement of the affected set.
func (ix *Index) Incremental(affected []model.CaseID) (*Report, []model.CaseID, error) {
	want := make(map[model.CaseID]bool, len(affected))
	var scope []model.CaseID
	for _, c := range affected {
		if !want[c] {
			want[c] = true
			scope = append(scope, c)
		}
	}
	sort.Slice(scope, func(i, j int) bool { return scope[i] < scope[j] })
	rep, err := ix.build(scope)
	if err != nil {
		return nil, nil, err
	}
	var skipped []model.CaseID
	for _, c := range ix.allCases {
		if !want[c] {
			skipped = append(skipped, c)
		}
	}
	return rep, skipped, nil
}

// build recomputes exactly the given cases.
func (ix *Index) build(cases []model.CaseID) (*Report, error) {
	rep := &Report{Cases: make(map[model.CaseID]*CaseSummary, len(cases)), CasesConsidered: len(cases)}
	for _, c := range cases {
		cs, err := ix.recomputeCase(c)
		if err != nil {
			return nil, err
		}
		rep.Cases[c] = cs
		rep.CaseRecomputes++
	}
	return rep, nil
}

// recomputeCase does the real per-case work: read every committed version's
// attachment bytes in both packs, verify the digest, and re-verify the two-root
// approval set and version chain.
func (ix *Index) recomputeCase(c model.CaseID) (*CaseSummary, error) {
	records := ix.byCase[c]
	if len(records) == 0 {
		return &CaseSummary{Case: c, Health: "ok", Attempts: ix.attemptsByCase[c]}, nil
	}
	sort.Slice(records, func(i, j int) bool { return records[i].acc.Version < records[j].acc.Version })

	cs := &CaseSummary{Case: c, Attempts: ix.attemptsByCase[c], Health: "ok"}
	var wantVersion uint64 = 1
	var wantPrev uint64 = 0
	for _, cm := range records {
		a := cm.acc
		// Version chain: 1, 2, 3, ... with prev linking to the previous.
		if a.Version != wantVersion || a.PrevVersion != wantPrev {
			cs.Problems = append(cs.Problems, fmt.Sprintf("v%d: version chain broken (want v%d prev %d)",
				a.Version, wantVersion, wantPrev))
			cs.Health = "corrupt"
		}
		wantVersion = a.Version + 1
		wantPrev = a.Version

		// Actual bytes in both packs.
		if len(a.Refs) != 2 {
			cs.Problems = append(cs.Problems, fmt.Sprintf("v%d: %d copies, want 2", a.Version, len(a.Refs)))
			cs.Health = "corrupt"
		}
		for _, sr := range a.Refs {
			content, _, err := ix.packs.read(sr)
			if err != nil {
				cs.Problems = append(cs.Problems, fmt.Sprintf("v%d: %v", a.Version, err))
				cs.Health = "corrupt"
				continue
			}
			if got := model.DigestOf(content); got != a.Digest {
				cs.Problems = append(cs.Problems, fmt.Sprintf("v%d: digest %s != %s", a.Version, got, a.Digest))
				cs.Health = "corrupt"
			}
		}
		// Two-root approval set over the exact binding.
		if err := ix.keyring.VerifyApprovalSet(a.Binding(), a.Approvals); err != nil {
			cs.Problems = append(cs.Problems, fmt.Sprintf("v%d: approval: %v", a.Version, err))
			cs.Health = "corrupt"
		}
		cs.Versions = append(cs.Versions, VersionSummary{Version: a.Version, Digest: a.Digest, CommittedSeq: cm.seq})
	}
	last := records[len(records)-1]
	cs.HighestVersion = last.acc.Version
	cs.Digest = last.acc.Digest
	cs.FromTenant = last.acc.FromTenant
	cs.ToTenant = last.acc.ToTenant
	cs.AuthGen = last.acc.AuthGen
	cs.CommittedSeq = last.seq
	return cs, nil
}

// EqualOnCases asserts two reports agree on exactly the given cases.
func EqualOnCases(full, inc *Report, cases []model.CaseID) error {
	for _, c := range cases {
		a, ok1 := full.Cases[c]
		b, ok2 := inc.Cases[c]
		if !ok1 || !ok2 {
			return fmt.Errorf("case %s missing (full=%v inc=%v)", c, ok1, ok2)
		}
		aj, _ := json.Marshal(a)
		bj, _ := json.Marshal(b)
		if !bytes.Equal(aj, bj) {
			return fmt.Errorf("case %s differs:\n full=%s\n inc =%s", c, aj, bj)
		}
	}
	if len(inc.Cases) != len(cases) {
		return fmt.Errorf("incremental covers %d cases, want %d", len(inc.Cases), len(cases))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Minimal independent log + pack readers.

type packFile struct {
	tenant model.TenantID
	raw    []byte
	// index maps content offset -> record bounds, built once so lookups are O(1).
	index map[int64]packRec
}

type packRec struct {
	contentStart int64
	contentEnd   int64
	headerStart  int64
	headerEnd    int64
}

type packSet map[model.TenantID]*packFile

func openPacks(dir string) (packSet, error) {
	entries, err := os.ReadDir(filepath.Join(dir, "packs"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return packSet{}, nil
		}
		return nil, err
	}
	out := packSet{}
	const prefix, suffix = "attachments-", ".bin"
	for _, e := range entries {
		name := e.Name()
		if len(name) <= len(prefix) || name[:len(prefix)] != prefix || name[len(name)-len(suffix):] != suffix {
			continue
		}
		tenant := model.TenantID(name[len(prefix) : len(name)-len(suffix)])
		raw, err := os.ReadFile(filepath.Join(dir, "packs", name))
		if err != nil {
			return nil, err
		}
		pf := &packFile{tenant: tenant, raw: raw, index: make(map[int64]packRec)}
		pf.buildIndex()
		out[tenant] = pf
	}
	return out, nil
}

// buildIndex walks the length-prefixed records once.
func (p *packFile) buildIndex() {
	pos := int64(0)
	for pos < int64(len(p.raw)) {
		if int64(len(p.raw))-pos < 8 {
			return
		}
		hlen := int64(binary.LittleEndian.Uint64(p.raw[pos : pos+8]))
		if hlen < 0 || pos+8+hlen+8 > int64(len(p.raw)) {
			return
		}
		chead := pos + 8 + hlen
		clen := int64(binary.LittleEndian.Uint64(p.raw[chead : chead+8]))
		contentStart := chead + 8
		if clen < 0 || contentStart+clen > int64(len(p.raw)) {
			return
		}
		p.index[contentStart] = packRec{
			contentStart: contentStart,
			contentEnd:   contentStart + clen,
			headerStart:  pos + 8,
			headerEnd:    chead,
		}
		pos = contentStart + clen
	}
}

func (ps packSet) read(sr model.SideRef) ([]byte, bool, error) {
	p := ps[sr.Tenant]
	if p == nil {
		return nil, false, fmt.Errorf("no pack for tenant %s", sr.Tenant)
	}
	rec, ok := p.index[sr.Offset]
	if !ok || rec.contentEnd-rec.contentStart != sr.Length {
		return nil, false, fmt.Errorf("pack %s: no record at offset %d (len %d)", sr.Tenant, sr.Offset, sr.Length)
	}
	return p.raw[rec.contentStart:rec.contentEnd], true, nil
}

func parseLog(path, domain string) ([]model.Record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []model.Record
	var prev model.Digest
	for len(raw) > 0 {
		nl := bytes.IndexByte(raw, '\n')
		if nl < 0 {
			break
		}
		line := raw[:nl]
		raw = raw[nl+1:]
		var rec model.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("record: %w", err)
		}
		if err := model.VerifyChain(domain, rec, prev); err != nil {
			return nil, err
		}
		prev = rec.Hash
		out = append(out, rec)
	}
	return out, nil
}
