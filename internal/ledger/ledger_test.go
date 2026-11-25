package ledger_test

import (
	"path/filepath"
	"testing"

	"handover/internal/audit"
	"handover/internal/fixture"
	"handover/internal/ledger"
	"handover/internal/model"
)

// newLedger opens a fresh ledger with the canonical two-department world.
func newLedger(t *testing.T) (*ledger.Ledger, *fixture.World) {
	t.Helper()
	w, err := fixture.NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	l, err := ledger.Open(ledger.Config{Dir: t.TempDir(), Keyring: w.Keyring})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	if err := l.EnsureGenesis("LEDGER-TEST", fixture.SortedTenants(w.TenantA, w.TenantB), w.GenesisCustodians()); err != nil {
		t.Fatal(err)
	}
	return l, w
}

func gen(l *ledger.Ledger) uint64 { return l.CurrentAuthGen() }

// submitV1 is a helper that builds and submits a valid first-version handover.
func submitV1(t *testing.T, l *ledger.Ledger, w *fixture.World, caseID model.CaseID, salt uint64) (ledger.Result, ledger.Request) {
	t.Helper()
	payload := fixture.Payload(caseID, 1, salt)
	req, err := w.SignedRequest(caseID, payload, w.TenantA, w.TenantB,
		"CUST-A1", "CUST-B1", 0, 1, gen(l))
	if err != nil {
		t.Fatal(err)
	}
	res, err := l.Submit(req)
	if err != nil {
		t.Fatalf("submit v1 %s: %v", caseID, err)
	}
	return res, req
}

func TestBasicAcceptAndAudit(t *testing.T) {
	l, w := newLedger(t)
	res, _ := submitV1(t, l, w, "CASE-1", 7)
	if res.Outcome != model.OutcomeAccepted {
		t.Fatalf("outcome = %q (%s), want accepted", res.Outcome, res.Reason)
	}
	rep, err := audit.Verify(l.Dir(), w.Keyring)
	if err != nil {
		t.Fatalf("audit: %v", err)
	}
	if !rep.OK() {
		t.Fatalf("audit problems: %v", rep.Problems)
	}
	if rep.Accepted != 1 {
		t.Fatalf("audit accepted = %d, want 1", rep.Accepted)
	}
	if got := rep.AcceptedByCase["CASE-1"]; got != 1 {
		t.Fatalf("audit case version = %d, want 1", got)
	}
}

func TestDuplicateSameContentIsDistinguished(t *testing.T) {
	l, w := newLedger(t)
	first, req := submitV1(t, l, w, "CASE-DUP", 3)
	if first.Outcome != model.OutcomeAccepted {
		t.Fatalf("first outcome = %q", first.Outcome)
	}
	// Re-send the exact same bytes with the same request ID and version.
	res, err := l.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != model.OutcomeDuplicate {
		t.Fatalf("retransmission outcome = %q (%s), want duplicate", res.Outcome, res.Reason)
	}
	if res.Committed != first.Committed {
		t.Fatalf("duplicate committed seq = %d, want original %d", res.Committed, first.Committed)
	}

	// A *different* payload under the same version must be a conflict, not a
	// duplicate.
	other := fixture.Payload("CASE-DUP", 1, 99)
	req2, err := w.SignedRequest("CASE-DUP", other, w.TenantA, w.TenantB,
		"CUST-A1", "CUST-B1", 0, 1, gen(l))
	if err != nil {
		t.Fatal(err)
	}
	res2, err := l.Submit(req2)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Outcome != model.OutcomeConflict {
		t.Fatalf("same-version-different-digest outcome = %q (%s), want conflict", res2.Outcome, res2.Reason)
	}
	if res2.Details["retained_digest"] != mustDigest(fixture.Payload("CASE-DUP", 1, 3)) {
		t.Fatalf("conflict retained digest = %q", res2.Details["retained_digest"])
	}
	if res2.Details["conflicting_digest"] != mustDigest(other) {
		t.Fatalf("conflict conflicting digest = %q", res2.Details["conflicting_digest"])
	}

	rep, err := audit.Verify(l.Dir(), w.Keyring)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("audit problems: %v", rep.Problems)
	}
	if rep.Duplicates != 1 || rep.Conflicts != 1 || rep.Accepted != 1 {
		t.Fatalf("audit counts accepted=%d dup=%d conflict=%d", rep.Accepted, rep.Duplicates, rep.Conflicts)
	}
}

func TestRevokedCustodianRejected(t *testing.T) {
	l, w := newLedger(t)
	// Revoke DEPT-A's custodian; this advances the auth generation.
	if err := l.Revoke(w.TenantA, "CUST-A1", "offboarding"); err != nil {
		t.Fatal(err)
	}
	// The request is correctly signed for the *new* generation but names the
	// revoked custodian, so custody must reject it.
	payload := fixture.Payload("CASE-REV", 1, 1)
	req, err := w.SignedRequest("CASE-REV", payload, w.TenantA, w.TenantB,
		"CUST-A1", "CUST-B1", 0, 1, gen(l))
	if err != nil {
		t.Fatal(err)
	}
	res, err := l.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != model.OutcomeRejected {
		t.Fatalf("outcome = %q, want rejected", res.Outcome)
	}
	if res.Reason != model.ReasonCustodianRevoked {
		t.Fatalf("reason = %q, want custodian_revoked", res.Reason)
	}
	if res.Details["tenant"] != string(w.TenantA) {
		t.Fatalf("details tenant = %q", res.Details["tenant"])
	}
}

func TestStaleAuthGenRejected(t *testing.T) {
	l, w := newLedger(t)
	stale := gen(l)
	if err := l.Grant(w.TenantA, "CUST-A2"); err != nil {
		t.Fatal(err)
	}
	payload := fixture.Payload("CASE-STALE", 1, 1)
	req, err := w.SignedRequest("CASE-STALE", payload, w.TenantA, w.TenantB,
		"CUST-A2", "CUST-B1", 0, 1, stale)
	if err != nil {
		t.Fatal(err)
	}
	res, err := l.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != model.OutcomeRejected || res.Reason != model.ReasonStaleAuthGen {
		t.Fatalf("outcome=%q reason=%q, want rejected/stale_auth_gen", res.Outcome, res.Reason)
	}
}

func TestApprovalMustBindBothTenantsAndDigest(t *testing.T) {
	l, w := newLedger(t)
	payload := fixture.Payload("CASE-BIND", 1, 1)

	// Approval set signed over a *different* digest must not verify.
	b := w.Binding("CASE-BIND", payload, w.TenantA, w.TenantB, 0, 1, gen(l))
	tampered := b
	tampered.Digest = model.DigestOf([]byte("something else"))
	req, err := w.SignedRequest("CASE-BIND", payload, w.TenantA, w.TenantB,
		"CUST-A1", "CUST-B1", 0, 1, gen(l))
	if err != nil {
		t.Fatal(err)
	}
	// Replace the approvals with ones over the wrong binding.
	req.Envelope.Approvals[0] = w.Signers()[w.TenantA].Sign(tampered)
	req.Envelope.Approvals[1] = w.Signers()[w.TenantB].Sign(tampered)
	res, err := l.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != model.OutcomeRejected || res.Reason != model.ReasonBadApproval {
		t.Fatalf("outcome=%q reason=%q, want rejected/bad_approval", res.Outcome, res.Reason)
	}
}

func mustDigest(b []byte) string { return model.DigestOf(b).String() }

func TestAuditDetectsTamperedAttachment(t *testing.T) {
	w, err := fixture.NewWorld()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	l, err := ledger.Open(ledger.Config{Dir: dir, Keyring: w.Keyring})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.EnsureGenesis("L", fixture.SortedTenants(w.TenantA, w.TenantB), w.GenesisCustodians()); err != nil {
		t.Fatal(err)
	}
	submitV1(t, l, w, "CASE-TAMP", 2)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}

	// Flip one byte inside the committed content in DEPT-B's pack.
	path := filepath.Join(dir, "packs", "attachments-DEPT-B.bin")
	tamperContentByte(t, path)

	rep, err := audit.Verify(dir, w.Keyring)
	if err == nil && rep.OK() {
		t.Fatal("audit passed despite tampered attachment")
	}
	if err != nil {
		t.Logf("audit error (acceptable): %v", err)
	} else if len(rep.Problems) == 0 {
		t.Fatal("expected audit problems")
	}
}

// tamperContentByte finds the last byte of the pack and flips it, which lands
// inside the last committed content.
func tamperContentByte(t *testing.T, path string) {
	t.Helper()
	data, err := readFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("empty pack")
	}
	data[len(data)-1] ^= 0xFF
	if err := writeFile(path, data); err != nil {
		t.Fatal(err)
	}
}
