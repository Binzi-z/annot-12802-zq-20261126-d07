package scenarios_test

import (
	"testing"

	"handover/internal/fixture"
	"handover/internal/model"
	"handover/internal/scenarios"
)

// TestPriorAcceptanceSurvivesLaterRevocation is the crux of the review: both
// departments stored the same digest and the handover was accepted while the
// custodian was active.  A revocation issued afterwards must not retroactively
// invalidate that acceptance.  The independent audit must still call the
// directory clean and the case healthy.
func TestPriorAcceptanceSurvivesLaterRevocation(t *testing.T) {
	env, cleanup, err := scenarios.TempEnv(false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	// Accept while CUST-A1 is active.
	res, _, err := env.V1("CASE-HIST", 1)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != model.OutcomeAccepted {
		t.Fatalf("pre-revocation accept outcome %q (%s)", res.Outcome, res.Reason)
	}
	// Revoke the custodian afterwards.
	if err := env.L.Revoke(env.W.TenantA, "CUST-A1", "post-hoc"); err != nil {
		t.Fatal(err)
	}

	// The historical acceptance stays valid: custody is evaluated at decision
	// time, not at audit time.
	rep, err := env.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("audit flagged a legitimately prior acceptance: %s", scenarios.Report(rep))
	}
	if rep.Accepted != 1 || rep.Rejected != 0 {
		t.Fatalf("audit counts: %s", scenarios.Report(rep))
	}
	if v := rep.AcceptedByCase["CASE-HIST"]; v != 1 {
		t.Fatalf("CASE-HIST highest version %d, want 1", v)
	}
}

// TestLateReplayAfterRevocationContrastsWithConflict distinguishes the two ways a
// revoked-side handover can arrive: an exact retransmission of an already
// accepted version is a duplicate (not a custody rejection), while a fresh
// version naming the revoked custodian is a custody rejection.
func TestLateReplayAfterRevocationContrastsWithConflict(t *testing.T) {
	env, cleanup, err := scenarios.TempEnv(false)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	first, req, err := env.V1("CASE-LATE2", 2)
	if err != nil {
		t.Fatal(err)
	}
	if first.Outcome != model.OutcomeAccepted {
		t.Fatalf("first accept %q", first.Outcome)
	}
	if err := env.L.Revoke(env.W.TenantA, "CUST-A1", "revoked-after-accept"); err != nil {
		t.Fatal(err)
	}

	// 1. Exact retransmission of the same version/content: duplicate, even though
	// custody has since changed.  Idempotency is checked before custody.
	dup, err := env.L.Submit(req)
	if err != nil {
		t.Fatal(err)
	}
	if dup.Outcome != model.OutcomeDuplicate {
		t.Fatalf("late retransmission outcome %q (%s), want duplicate", dup.Outcome, dup.Reason)
	}

	// 2. A brand-new version naming the revoked custodian: rejected with
	// custodian_revoked.
	next, err := env.SubmitPayload("CASE-LATE2", 2, 1, fixture.Payload("CASE-LATE2", 2, 9),
		env.W.TenantA, env.W.TenantB, "CUST-A1", "CUST-B1", env.L.CurrentAuthGen())
	if err != nil {
		t.Fatal(err)
	}
	if next.Outcome != model.OutcomeRejected || next.Reason != model.ReasonCustodianRevoked {
		t.Fatalf("new version under revoked custodian outcome=%q reason=%q, want rejected/custodian_revoked",
			next.Outcome, next.Reason)
	}

	rep, err := env.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("audit: %s", scenarios.Report(rep))
	}
	if rep.Duplicates != 1 || rep.Rejected != 1 || rep.Accepted != 1 {
		t.Fatalf("audit counts: %s", scenarios.Report(rep))
	}
}
