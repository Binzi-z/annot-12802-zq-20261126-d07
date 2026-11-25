package exhaustive_test

import (
	"fmt"
	"testing"

	"handover/internal/audit"
	"handover/internal/exhaustive"
	"handover/internal/fixture"
	"handover/internal/ledger"
	"handover/internal/model"
)

// runPermutation builds a fresh ledger and reference, applies ops in the given
// order, and requires per-op agreement plus a clean independent audit.
func runPermutation(t *testing.T, ops []exhaustive.Op) {
	t.Helper()
	w, err := fixture.NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	l, err := ledger.Open(ledger.Config{Dir: dir, Keyring: w.Keyring})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.EnsureGenesis("LEDGER-EXH", fixture.SortedTenants(w.TenantA, w.TenantB), w.GenesisCustodians()); err != nil {
		t.Fatal(err)
	}

	real, err := exhaustive.RunReal(l, w, ops)
	if err != nil {
		t.Fatalf("real run (%v): %v", ops, err)
	}

	ref := exhaustive.NewRef(w)
	want := make([]exhaustive.Outcome, len(ops))
	for i, op := range ops {
		want[i] = ref.Apply(op)
	}

	for i := range ops {
		if real[i].Outcome != want[i].Outcome || real[i].Reason != want[i].Reason {
			t.Fatalf("op %d %s: real=(%q,%q) ref=(%q,%q)\n  sequence: %v",
				i, ops[i], real[i].Outcome, real[i].Reason, want[i].Outcome, want[i].Reason, ops)
		}
	}

	// The independent audit must accept the directory for every ordering.
	rep, err := audit.Verify(dir, w.Keyring)
	if err != nil {
		t.Fatalf("audit (%v): %v", ops, err)
	}
	if !rep.OK() {
		t.Fatalf("audit problems for %v: %v", ops, rep.Problems)
	}
}

// TestExhaustiveNoRevoke enumerates all 120 orderings of a grant/submit set that
// mixes a grant, a duplicate retransmission, a version gap candidate and a
// second case.
func TestExhaustiveNoRevoke(t *testing.T) {
	a := model.TenantID("DEPT-A")
	ops := []exhaustive.Op{
		{Kind: exhaustive.KindGrant, Tenant: a, Custodian: "CUST-A2"},
		{Kind: exhaustive.KindSubmit, Case: "CASE-E", Version: 1, Prev: 0, Salt: 1, AuthGen: 2, FromCust: "CUST-A1", ToCust: "CUST-B1"},
		{Kind: exhaustive.KindSubmit, Case: "CASE-E", Version: 1, Prev: 0, Salt: 1, AuthGen: 2, FromCust: "CUST-A1", ToCust: "CUST-B1"},
		{Kind: exhaustive.KindSubmit, Case: "CASE-E", Version: 2, Prev: 1, Salt: 2, AuthGen: 2, FromCust: "CUST-A1", ToCust: "CUST-B1"},
		{Kind: exhaustive.KindSubmit, Case: "CASE-F", Version: 1, Prev: 0, Salt: 3, AuthGen: 2, FromCust: "CUST-A1", ToCust: "CUST-B1"},
	}
	perms := exhaustive.Permutations(ops)
	if len(perms) != 120 {
		t.Fatalf("got %d permutations, want 120", len(perms))
	}
	for i, perm := range perms {
		t.Run(fmt.Sprintf("perm%03d", i), func(t *testing.T) { runPermutation(t, perm) })
	}
}

// TestExhaustiveRevoke enumerates both orderings of "revoke persisted" against
// "late receipt": the submit is either accepted (first) or rejected as
// custodian_revoked (second).
func TestExhaustiveRevoke(t *testing.T) {
	b := model.TenantID("DEPT-B")
	ops := []exhaustive.Op{
		{Kind: exhaustive.KindRevoke, Tenant: b, Custodian: "CUST-B1"},
		{Kind: exhaustive.KindSubmit, Case: "CASE-R", Version: 1, Prev: 0, Salt: 5, AuthGen: 2, FromCust: "CUST-A1", ToCust: "CUST-B1"},
	}
	perms := exhaustive.Permutations(ops)
	if len(perms) != 2 {
		t.Fatalf("got %d permutations, want 2", len(perms))
	}
	sawAccepted, sawRevoked := false, false
	for i, perm := range perms {
		// Track which outcome order 0 (revoke-first) and order 1 (submit-first)
		// should produce by checking directly.
		real := runAndReturn(t, perm)
		for _, oc := range real {
			if oc.Outcome == model.OutcomeAccepted {
				sawAccepted = true
			}
			if oc.Reason == model.ReasonCustodianRevoked {
				sawRevoked = true
			}
		}
		t.Logf("perm %d %v -> %v", i, perm, real)
	}
	if !sawAccepted || !sawRevoked {
		t.Fatalf("expected both an accepted and a revoked-rejected ordering; accepted=%v revoked=%v", sawAccepted, sawRevoked)
	}
}

func runAndReturn(t *testing.T, ops []exhaustive.Op) []exhaustive.Outcome {
	t.Helper()
	w, err := fixture.NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	l, err := ledger.Open(ledger.Config{Dir: dir, Keyring: w.Keyring})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.EnsureGenesis("LEDGER-EXH2", fixture.SortedTenants(w.TenantA, w.TenantB), w.GenesisCustodians()); err != nil {
		t.Fatal(err)
	}
	real, err := exhaustive.RunReal(l, w, ops)
	if err != nil {
		t.Fatal(err)
	}
	ref := exhaustive.NewRef(w)
	for i, op := range ops {
		want := ref.Apply(op)
		if real[i].Outcome != want.Outcome || real[i].Reason != want.Reason {
			t.Fatalf("op %d %s: real=(%q,%q) ref=(%q,%q)", i, op, real[i].Outcome, real[i].Reason, want.Outcome, want.Reason)
		}
	}
	return real
}
