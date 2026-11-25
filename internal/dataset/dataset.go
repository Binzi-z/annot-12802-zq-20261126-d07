// Package dataset generates the large multi-case corpus used by the scale test:
// 50,000 handover records spread across many cases, with a realistic mix of
// revisions so the incremental report has something to restrict to.
package dataset

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"handover/internal/fixture"
	"handover/internal/ledger"
	"handover/internal/model"
)

// Options controls corpus shape.  With Cases=20000 and MaxVersions=4 the corpus
// is exactly 50,000 records: each case gets 1..4 contiguous revisions, evenly.
type Options struct {
	Cases       int
	MaxVersions int
	Seed        uint64
}

// DefaultOptions produces 50,000 records across 20,000 cases.
func DefaultOptions() Options { return Options{Cases: 20000, MaxVersions: 4, Seed: 12802} }

// Stats reports what was generated.
type Stats struct {
	Cases     int
	Records   int
	Dir       string
	Affected  []model.CaseID
	ByVersion map[uint64]int
}

// Generate writes a corpus into a fresh ledger under dir.  It returns the record
// count and the affected set for an incremental run.  fsync is disabled for
// speed; the crash scenarios cover durability.
func Generate(dir string, w *fixture.World, opts Options) (*Stats, error) {
	if opts.Cases <= 0 || opts.MaxVersions <= 0 {
		return nil, fmt.Errorf("dataset: need positive cases and max versions")
	}
	l, err := ledger.Open(ledger.Config{Dir: dir, Keyring: w.Keyring, Sync: false})
	if err != nil {
		return nil, err
	}
	defer l.Close()
	if err := l.EnsureGenesis("LEDGER-BULK", fixture.SortedTenants(w.TenantA, w.TenantB), w.GenesisCustodians()); err != nil {
		return nil, err
	}

	st := &Stats{Dir: dir, ByVersion: make(map[uint64]int)}
	cases := make([]model.CaseID, opts.Cases)
	for i := range cases {
		cases[i] = model.CaseID(fmt.Sprintf("CASE-%06d", i))
	}

	// Each case receives a contiguous run of revisions 1..depth(i).  Contiguity
	// is required: the ledger enforces prev_version == highest accepted version.
	for i, c := range cases {
		depth := 1 + i%opts.MaxVersions
		for v := 1; v <= depth; v++ {
			if err := submitVersion(l, w, c, uint64(v), uint64(v-1), opts.Seed+uint64(i)*100+uint64(v)); err != nil {
				return nil, fmt.Errorf("case %s v%d: %w", c, v, err)
			}
			st.Records++
			st.ByVersion[uint64(v)]++
		}
	}
	st.Cases = len(cases)

	// The affected set: cases that received the most recent revision (the tail
	// of the corpus), i.e. the "last batch" an incremental run would recompute.
	affected := make(map[model.CaseID]bool)
	for i, c := range cases {
		if 1+i%opts.MaxVersions == opts.MaxVersions {
			affected[c] = true
		}
	}
	for c := range affected {
		st.Affected = append(st.Affected, c)
	}
	sort.Slice(st.Affected, func(i, j int) bool { return st.Affected[i] < st.Affected[j] })
	return st, nil
}

func submitVersion(l *ledger.Ledger, w *fixture.World, c model.CaseID, version, prev, salt uint64) error {
	payload := fixture.Payload(c, version, salt)
	req, err := w.SignedRequest(c, payload, w.TenantA, w.TenantB,
		"CUST-A1", "CUST-B1", prev, version, l.CurrentAuthGen())
	if err != nil {
		return err
	}
	if _, err := l.Submit(req); err != nil {
		return err
	}
	return nil
}

// DirSize sums the sizes of files under dir.
func DirSize(dir string) (int64, error) {
	var total int64
	err := filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}
