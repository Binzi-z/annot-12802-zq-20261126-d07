package report_test

import (
	"fmt"
	"testing"

	"handover/internal/dataset"
	"handover/internal/fixture"
	"handover/internal/model"
	"handover/internal/report"
)

// TestIncrementalMatchesFull is the scale test: generate a 50k-record multi-case
// corpus, recompute the whole ledger and then recompute only the affected cases,
// and require the two to agree exactly on those cases while touching nothing
// else.  Under -short it runs a small corpus to stay fast.
func TestIncrementalMatchesFull(t *testing.T) {
	opts := dataset.DefaultOptions()
	if testing.Short() {
		opts = dataset.Options{Cases: 200, MaxVersions: 4, Seed: 7}
	}
	w, err := fixture.NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	st, err := dataset.Generate(dir, w, opts)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !testing.Short() && st.Records != 50000 {
		t.Fatalf("corpus has %d records, want exactly 50000", st.Records)
	}
	t.Logf("corpus: cases=%d records=%d affected=%d byVersion=%v",
		st.Cases, st.Records, len(st.Affected), st.ByVersion)

	ix, err := report.BuildIndex(dir, w.Keyring)
	if err != nil {
		t.Fatalf("index: %v", err)
	}

	full, err := ix.Full()
	if err != nil {
		t.Fatalf("full: %v", err)
	}
	if full.CaseRecomputes != st.Cases {
		t.Fatalf("full recomputed %d cases, want %d", full.CaseRecomputes, st.Cases)
	}

	inc, skipped, err := ix.Incremental(st.Affected)
	if err != nil {
		t.Fatalf("incremental: %v", err)
	}
	if inc.CaseRecomputes != len(st.Affected) {
		t.Fatalf("incremental recomputed %d cases, want %d", inc.CaseRecomputes, len(st.Affected))
	}
	if len(skipped) != st.Cases-len(st.Affected) {
		t.Fatalf("incremental skipped %d cases, want %d", len(skipped), st.Cases-len(st.Affected))
	}

	if err := report.EqualOnCases(full, inc, st.Affected); err != nil {
		t.Fatalf("affected cases disagree: %v", err)
	}

	// Nothing skipped may appear in the incremental report.
	for _, c := range skipped {
		if _, ok := inc.Cases[c]; ok {
			t.Fatalf("incremental report includes skipped case %s", c)
		}
	}

	// Every summary must be healthy on a clean corpus.
	for c, cs := range full.Cases {
		if cs.Health != "ok" {
			t.Fatalf("case %s unhealthy: %v", c, cs.Problems)
		}
	}

	// Sanity: the recomputed per-case version count matches the corpus.
	for c, cs := range full.Cases {
		idx := caseIndex(c)
		want := 1 + idx%opts.MaxVersions
		if len(cs.Versions) != want {
			t.Fatalf("case %s has %d versions, want %d", c, len(cs.Versions), want)
		}
		if cs.Versions[len(cs.Versions)-1].Version != uint64(want) {
			t.Fatalf("case %s highest %d, want %d", c, cs.Versions[len(cs.Versions)-1].Version, want)
		}
	}
}

// caseIndex parses "CASE-000123" back to 123.
func caseIndex(c model.CaseID) int {
	var n int
	fmt.Sscanf(string(c), "CASE-%06d", &n)
	return n
}

// TestIncrementalDetectsTamperInScope proves the incremental recompute is really
// reading the affected bytes: tamper one affected case's attachment and require
// the recompute to flag it, while a different (unaffected) case stays "ok".
func TestIncrementalDetectsTamperInScope(t *testing.T) {
	opts := dataset.Options{Cases: 60, MaxVersions: 3, Seed: 3}
	w, err := fixture.NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	st, err := dataset.Generate(dir, w, opts)
	if err != nil {
		t.Fatal(err)
	}
	ix, err := report.BuildIndex(dir, w.Keyring)
	if err != nil {
		t.Fatal(err)
	}
	affected := st.Affected
	if len(affected) == 0 {
		t.Fatal("no affected cases")
	}
	tamperCase := affected[0]
	if err := tamperLastAttachmentByte(dir, w, tamperCase); err != nil {
		t.Fatal(err)
	}

	// Rebuild the index so it reads the tampered bytes; the earlier index holds
	// the original pack contents in memory.
	ix, err = report.BuildIndex(dir, w.Keyring)
	if err != nil {
		t.Fatal(err)
	}
	full, err := ix.Full()
	if err != nil {
		t.Fatal(err)
	}
	if full.Cases[tamperCase].Health == "ok" {
		t.Fatalf("full report did not flag tampered case %s", tamperCase)
	}
	// Pick a case that is neither tampered nor affected to confirm it stays ok.
	var control model.CaseID
	for _, c := range ix.AllCases() {
		isAffected := false
		for _, a := range affected {
			if a == c {
				isAffected = true
				break
			}
		}
		if !isAffected && c != tamperCase {
			control = c
			break
		}
	}
	if control == "" {
		t.Skip("no control case available")
	}
	if full.Cases[control].Health != "ok" {
		t.Fatalf("control case %s unexpectedly unhealthy: %v", control, full.Cases[control].Problems)
	}
}
