// Package audit is an *independent* verifier for a handover ledger directory.
//
// It deliberately does not import the ledger, wire or fixture packages and
// re-implements log parsing, pack parsing, custody replay and the approval
// policy from the on-disk bytes.  Sharing only the immutable crypto/encoding
// types in internal/model means a policy bug in the ledger cannot make the
// audit agree with it by construction.
//
// The audit recomputes, from the actual attachments and the reconciliation log:
//
//   - both hash chains and sequence continuity;
//   - every committed handover's digest against the actual bytes in both packs;
//   - the two-root approval set over the exact binding;
//   - custody (grant/revoke) and the version baseline at each attempt's recorded
//     journal head;
//   - the declared outcome and reason of every attempt by replaying the same
//     documented policy order.
package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"handover/internal/model"
)

// Problem is one audit finding.
type Problem struct {
	Scope   string
	Ref     string
	Message string
}

func (p Problem) String() string { return fmt.Sprintf("[%s %s] %s", p.Scope, p.Ref, p.Message) }

// Report is the full audit result.
type Report struct {
	JournalRecords int
	ReconRecords   int
	Attempts       int
	Accepted       int
	Duplicates     int
	Conflicts      int
	Rejected       int
	Recovered      int
	Problems       []Problem

	// AcceptedByCase is the recomputed committed state: case -> highest version.
	AcceptedByCase map[model.CaseID]uint64
}

// OK reports whether the audit found no problems.
func (r *Report) OK() bool { return len(r.Problems) == 0 }

// Verify audits the ledger directory against the trusted keyring.
func Verify(dir string, keyring *model.Keyring) (*Report, error) {
	rep := &Report{AcceptedByCase: make(map[model.CaseID]uint64)}

	journal, err := parseLog(filepath.Join(dir, "journal.jsonl"), model.JournalDomain)
	if err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	recon, err := parseLog(filepath.Join(dir, "reconciled.jsonl"), model.ReconDomain)
	if err != nil {
		return nil, fmt.Errorf("recon: %w", err)
	}
	rep.JournalRecords = len(journal)
	rep.ReconRecords = len(recon)

	packs, err := openPacks(dir)
	if err != nil {
		return nil, err
	}

	if !rep.checkChains(journal, recon) {
		return rep, nil
	}

	ref := buildReference(journal, recon)

	// Cross-check the recon custody mirror against the authoritative journal.
	rep.crossCheckCustody(ref)

	// Verify every committed handover against the actual bytes.
	for _, rec := range journal {
		if rec.Type != model.TypeAccept {
			continue
		}
		var a model.AcceptPayload
		if err := json.Unmarshal(rec.Payload, &a); err != nil {
			rep.Problems = append(rep.Problems, Problem{"journal", fmt.Sprint(rec.Seq), err.Error()})
			continue
		}
		rep.checkCommit(rec.Seq, a, packs, keyring)
		if a.Version > rep.AcceptedByCase[a.Case] {
			rep.AcceptedByCase[a.Case] = a.Version
		}
	}

	// Replay every reconciliation attempt.
	for _, rec := range recon {
		if rec.Type != model.ReconAttempt {
			continue
		}
		var at model.AttemptPayload
		if err := json.Unmarshal(rec.Payload, &at); err != nil {
			rep.Problems = append(rep.Problems, Problem{"recon", fmt.Sprint(rec.Seq), err.Error()})
			continue
		}
		rep.Attempts++
		switch at.Outcome {
		case model.OutcomeAccepted:
			rep.Accepted++
		case model.OutcomeDuplicate:
			rep.Duplicates++
		case model.OutcomeConflict:
			rep.Conflicts++
		case model.OutcomeRejected:
			rep.Rejected++
		default:
			rep.Problems = append(rep.Problems, Problem{"attempt", at.RequestID, "unknown outcome " + string(at.Outcome)})
		}
		if at.Recovered {
			rep.Recovered++
		}
		rep.checkAttempt(ref, at, packs, keyring)
	}

	rep.reconcileCommits(ref, recon)
	return rep, nil
}

func (r *Report) checkChains(journal, recon []model.Record) bool {
	ok := true
	check := func(name, domain string, recs []model.Record) {
		var prev model.Digest
		for i, rec := range recs {
			if rec.Seq != uint64(i+1) {
				r.Problems = append(r.Problems, Problem{name, fmt.Sprint(rec.Seq),
					fmt.Sprintf("sequence gap: want %d", i+1)})
				ok = false
			}
			if err := model.VerifyChain(domain, rec, prev); err != nil {
				r.Problems = append(r.Problems, Problem{name, fmt.Sprint(rec.Seq), err.Error()})
				ok = false
			}
			prev = rec.Hash
		}
	}
	check("journal", model.JournalDomain, journal)
	check("recon", model.ReconDomain, recon)
	return ok
}

func (r *Report) checkCommit(seq uint64, a model.AcceptPayload, packs packSet, keyring *model.Keyring) {
	ref := fmt.Sprintf("%s/v%d@%d", a.Case, a.Version, seq)
	if len(a.Refs) != 2 {
		r.Problems = append(r.Problems, Problem{"journal", ref, "accept must reference exactly two department copies"})
		return
	}
	seenTenant := map[model.TenantID]bool{}
	for _, sr := range a.Refs {
		seenTenant[sr.Tenant] = true
		content, meta, err := packs.read(sr)
		if err != nil {
			r.Problems = append(r.Problems, Problem{"pack", ref, err.Error()})
			continue
		}
		if got := digestOf(content); got != a.Digest {
			r.Problems = append(r.Problems, Problem{"pack", ref,
				fmt.Sprintf("actual bytes digest %s != committed %s", got, a.Digest)})
		}
		if got := digestOf(content); got != sr.Digest {
			r.Problems = append(r.Problems, Problem{"pack", ref,
				fmt.Sprintf("actual bytes digest %s != reference %s", got, sr.Digest)})
		}
		if meta.Kind != model.PackKindCandidate {
			r.Problems = append(r.Problems, Problem{"pack", ref, "committed copy has kind " + meta.Kind})
		}
		if meta.Meta.Case != a.Case || meta.Meta.Version != a.Version ||
			meta.Meta.Digest != a.Digest || meta.Meta.RequestID != a.RequestID {
			r.Problems = append(r.Problems, Problem{"pack", ref,
				"pack metadata does not match the committed handover"})
		}
	}
	if !seenTenant[a.FromTenant] || !seenTenant[a.ToTenant] {
		r.Problems = append(r.Problems, Problem{"journal", ref,
			"does not have one copy per department"})
	}
	if err := keyring.VerifyApprovalSet(a.Binding(), a.Approvals); err != nil {
		r.Problems = append(r.Problems, Problem{"journal", ref, "approval set: " + err.Error()})
	}
}

// reconcileCommits ensures the audit log and the journal tell the same story.
func (r *Report) reconcileCommits(ref *reference, recon []model.Record) {
	acceptedSeqs := make(map[uint64]int)
	for _, rec := range recon {
		if rec.Type != model.ReconAttempt {
			continue
		}
		var at model.AttemptPayload
		if json.Unmarshal(rec.Payload, &at) != nil {
			continue
		}
		if at.Outcome == model.OutcomeAccepted && at.CommittedSeq != 0 {
			acceptedSeqs[at.CommittedSeq]++
		}
	}
	for _, c := range ref.commits {
		switch n := acceptedSeqs[c.seq]; {
		case n == 0:
			r.Problems = append(r.Problems, Problem{"attempt", fmt.Sprintf("%s/v%d", c.caseID, c.version),
				fmt.Sprintf("journal commit seq %d has no accepted audit record", c.seq)})
		case n > 1:
			r.Problems = append(r.Problems, Problem{"attempt", fmt.Sprintf("%s/v%d", c.caseID, c.version),
				fmt.Sprintf("journal commit seq %d recorded %d times", c.seq, n)})
		}
	}
}

// ---------------------------------------------------------------------------
// Reference state recomputed from the journal.

type commitMark struct {
	caseID  model.CaseID
	version uint64
	digest  model.Digest
	from    model.TenantID
	to      model.TenantID
	seq     uint64
}

type custodyEvent struct {
	seq       uint64
	tenant    model.TenantID
	custodian string
	grant     bool
	authGen   uint64
}

type reference struct {
	commits []commitMark
	events  []custodyEvent
	// reconEvents is the mirror as recorded in the audit log.
	reconEvents []custodyEvent
}

func buildReference(journal, recon []model.Record) *reference {
	ref := &reference{}
	for _, rec := range journal {
		switch rec.Type {
		case model.TypeAccept:
			var a model.AcceptPayload
			if json.Unmarshal(rec.Payload, &a) == nil {
				ref.commits = append(ref.commits, commitMark{
					caseID: a.Case, version: a.Version, digest: a.Digest,
					from: a.FromTenant, to: a.ToTenant, seq: rec.Seq,
				})
			}
		case model.TypeGrant:
			var g model.GrantPayload
			if json.Unmarshal(rec.Payload, &g) == nil {
				ref.events = append(ref.events, custodyEvent{rec.Seq, g.Tenant, g.Custodian, true, g.AuthGen})
			}
		case model.TypeRevoke:
			var r model.RevokePayload
			if json.Unmarshal(rec.Payload, &r) == nil {
				ref.events = append(ref.events, custodyEvent{rec.Seq, r.Tenant, r.Custodian, false, r.AuthGen})
			}
		}
	}
	for _, rec := range recon {
		if rec.Type != model.ReconGrant && rec.Type != model.ReconRevoke {
			continue
		}
		var m model.MirrorPayload
		if json.Unmarshal(rec.Payload, &m) == nil {
			ref.reconEvents = append(ref.reconEvents, custodyEvent{m.JournalSeq, m.Tenant, m.Custodian, m.Grant, m.AuthGen})
		}
	}
	return ref
}

// snapshotAt recomputes a custodian's custody from journal events at or before
// head.
func snapshotAt(events []custodyEvent, head uint64, t model.TenantID, custodian string) model.CustodySnapshot {
	active := ""
	granted := false
	var revokedAt uint64
	for _, e := range events {
		if e.seq > head || e.tenant != t {
			continue
		}
		if e.grant {
			if e.custodian == custodian {
				granted = true
				revokedAt = 0
			}
			active = e.custodian
		} else {
			if e.custodian == custodian && revokedAt == 0 {
				revokedAt = e.seq
			}
			if active == e.custodian {
				active = ""
			}
		}
	}
	snap := model.CustodySnapshot{Tenant: t, Custodian: custodian}
	switch {
	case !granted:
		snap.Status = model.CustodyUnknown
	case active == custodian && revokedAt == 0:
		snap.Status = model.CustodyActive
	default:
		snap.Status = model.CustodyRevoked
		snap.RevokeSeq = revokedAt
	}
	return snap
}

func authGenAt(events []custodyEvent, head uint64) uint64 {
	var gen uint64
	for _, e := range events {
		if e.seq <= head && e.authGen > gen {
			gen = e.authGen
		}
	}
	return gen
}

func baselineAt(commits []commitMark, head uint64, c model.CaseID) uint64 {
	var max uint64
	for _, cm := range commits {
		if cm.seq <= head && cm.caseID == c && cm.version > max {
			max = cm.version
		}
	}
	return max
}

func digestAt(commits []commitMark, head uint64, c model.CaseID, version uint64) (commitMark, bool) {
	for _, cm := range commits {
		if cm.seq <= head && cm.caseID == c && cm.version == version {
			return cm, true
		}
	}
	return commitMark{}, false
}

func (r *Report) crossCheckCustody(ref *reference) {
	if a, b := authGenAt(ref.events, ^uint64(0)), authGenAt(ref.reconEvents, ^uint64(0)); a != b {
		r.Problems = append(r.Problems, Problem{"recon", "auth_gen",
			fmt.Sprintf("journal %d != recon mirror %d", a, b)})
	}
	if len(ref.events) != len(ref.reconEvents) {
		r.Problems = append(r.Problems, Problem{"recon", "custody",
			fmt.Sprintf("journal has %d custody events, recon mirror has %d", len(ref.events), len(ref.reconEvents))})
		return
	}
	for i := range ref.events {
		je, re := ref.events[i], ref.reconEvents[i]
		if je != re {
			r.Problems = append(r.Problems, Problem{"recon", fmt.Sprint(je.seq),
				"recon custody mirror disagrees with the journal"})
		}
	}
}

// ---------------------------------------------------------------------------
// Independent policy replay of one attempt.

func (r *Report) checkAttempt(ref *reference, at model.AttemptPayload, packs packSet, keyring *model.Keyring) {
	refs := fmt.Sprintf("%s/v%d", at.Case, at.Version)
	head := at.JournalHeadAtDecision
	add := func(msg string) { r.Problems = append(r.Problems, Problem{"attempt", refs, msg}) }

	// Recomputed context at the recorded head.
	wantFrom := snapshotAt(ref.events, head, at.FromTenant, at.FromCustodian)
	wantTo := snapshotAt(ref.events, head, at.ToTenant, at.ToCustodian)
	wantGen := authGenAt(ref.events, head)
	wantBaseline := baselineAt(ref.commits, head, at.Case)

	if at.FromCustody != wantFrom {
		add(fmt.Sprintf("from custody %s/%s, replay at head %d says %s/%s",
			at.FromCustody.Custodian, at.FromCustody.Status, head, wantFrom.Custodian, wantFrom.Status))
	}
	if at.ToCustody != wantTo {
		add(fmt.Sprintf("to custody %s/%s, replay at head %d says %s/%s",
			at.ToCustody.Custodian, at.ToCustody.Status, head, wantTo.Custodian, wantTo.Status))
	}
	if at.GlobalAuthGen != wantGen {
		add(fmt.Sprintf("global auth gen %d, replay at head %d says %d", at.GlobalAuthGen, head, wantGen))
	}
	if at.PrevAcceptedVersion != wantBaseline {
		add(fmt.Sprintf("prev accepted version %d, replay at head %d says %d", at.PrevAcceptedVersion, head, wantBaseline))
	}

	// Recompute the whole policy outcome.
	apprErr := keyring.VerifyApprovalSet(at.Binding(), at.Approvals)
	expected, reason := classify(at, ref, head, wantBaseline, wantFrom, wantTo, wantGen, apprErr)

	if expected != at.Outcome {
		add(fmt.Sprintf("recorded outcome %q, independent replay says %q (reason %q)",
			at.Outcome, expected, reason))
		return
	}
	if expected == model.OutcomeRejected && at.Reason != reason {
		add(fmt.Sprintf("recorded reason %q, replay says %q", at.Reason, reason))
	}

	// An accepted attempt must point at bytes that actually match its digest in
	// both departments.
	if at.Outcome == model.OutcomeAccepted {
		seen := map[model.TenantID]bool{}
		for _, sr := range at.Refs {
			seen[sr.Tenant] = true
			content, _, err := packs.read(sr)
			if err != nil {
				add("accepted attempt: " + err.Error())
				continue
			}
			if got := digestOf(content); got != at.Digest {
				add(fmt.Sprintf("accepted attempt bytes digest %s != %s", got, at.Digest))
			}
		}
		if !seen[at.FromTenant] || !seen[at.ToTenant] {
			add("accepted attempt lacks one copy per department")
		}
	}
}

func classify(at model.AttemptPayload, ref *reference, head, baseline uint64,
	from, to model.CustodySnapshot, wantGen uint64, apprErr error) (model.Outcome, string) {

	// 1. Shape.
	if err := at.Binding().ValidateShape(); err != nil {
		return model.OutcomeRejected, model.ReasonBadBinding
	}
	// 2. Attachment integrity.
	if !at.PayloadPresent {
		return model.OutcomeRejected, model.ReasonMissingPayload
	}
	if at.ActualDigest != at.Digest {
		return model.OutcomeRejected, model.ReasonDigestMismatch
	}
	// 3. Version-level idempotency against commits known at the head.
	if prev, ok := digestAt(ref.commits, head, at.Case, at.Version); ok {
		if prev.digest == at.Digest && prev.from == at.FromTenant && prev.to == at.ToTenant {
			return model.OutcomeDuplicate, ""
		}
		return model.OutcomeConflict, ""
	}
	// 4. Custody.
	if from.Status != model.CustodyActive {
		return model.OutcomeRejected, custodyReason(from.Status)
	}
	if to.Status != model.CustodyActive {
		return model.OutcomeRejected, custodyReason(to.Status)
	}
	// 5. Authorization generation.
	if at.AuthGen != wantGen {
		return model.OutcomeRejected, model.ReasonStaleAuthGen
	}
	// 6. Approvals.
	if apprErr != nil {
		return model.OutcomeRejected, model.ReasonBadApproval
	}
	// 7. Version sequencing.
	if at.Version > baseline+1 {
		return model.OutcomeRejected, model.ReasonVersionGap
	}
	if at.PrevVersion != baseline {
		return model.OutcomeRejected, model.ReasonStalePrevious
	}
	return model.OutcomeAccepted, ""
}

func custodyReason(status string) string {
	if status == model.CustodyRevoked {
		return model.ReasonCustodianRevoked
	}
	return model.ReasonCustodianUnknown
}

// ---------------------------------------------------------------------------
// Minimal independent readers (no imports from internal/wire).

type packFile struct {
	tenant model.TenantID
	raw    []byte
}

type packHeader struct {
	Kind string         `json:"kind"`
	Meta model.PackMeta `json:"meta"`
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
	for _, e := range entries {
		name := e.Name()
		const prefix, suffix = "attachments-", ".bin"
		if len(name) <= len(prefix) || name[:len(prefix)] != prefix || name[len(name)-len(suffix):] != suffix {
			continue
		}
		tenant := model.TenantID(name[len(prefix) : len(name)-len(suffix)])
		raw, err := os.ReadFile(filepath.Join(dir, "packs", name))
		if err != nil {
			return nil, err
		}
		out[tenant] = &packFile{tenant: tenant, raw: raw}
	}
	return out, nil
}

// read walks the length-prefixed records to find the one at (off,length) and
// returns its content and header.
func (ps packSet) read(sr model.SideRef) ([]byte, packHeader, error) {
	var hdr packHeader
	p := ps[sr.Tenant]
	if p == nil {
		return nil, hdr, fmt.Errorf("no pack for tenant %s", sr.Tenant)
	}
	raw := p.raw
	pos := int64(0)
	for pos < int64(len(raw)) {
		if int64(len(raw))-pos < 8 {
			break
		}
		hlen := int64(binary.LittleEndian.Uint64(raw[pos : pos+8]))
		if hlen < 0 || pos+8+hlen+8 > int64(len(raw)) {
			break
		}
		chead := pos + 8 + hlen
		clen := int64(binary.LittleEndian.Uint64(raw[chead : chead+8]))
		contentStart := chead + 8
		if clen < 0 || contentStart+clen > int64(len(raw)) {
			break
		}
		if contentStart == sr.Offset && clen == sr.Length {
			if err := json.Unmarshal(raw[pos+8:chead], &hdr); err != nil {
				return nil, hdr, fmt.Errorf("pack %s header at %d: %w", sr.Tenant, sr.Offset, err)
			}
			return raw[contentStart : contentStart+clen], hdr, nil
		}
		pos = contentStart + clen
	}
	return nil, hdr, fmt.Errorf("pack %s: no record at content offset %d (len %d)", sr.Tenant, sr.Offset, sr.Length)
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
			break // torn tail; the writer truncates it on open
		}
		line := raw[:nl]
		raw = raw[nl+1:]
		var rec model.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("record: %w", err)
		}
		if err := model.VerifyChain(domain, rec, prev); err != nil {
			return out, err
		}
		prev = rec.Hash
		out = append(out, rec)
	}
	return out, nil
}

func digestOf(b []byte) model.Digest { return sha256.Sum256(b) }
