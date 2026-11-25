package scenarios_test

import (
	"testing"

	"handover/internal/model"
	"handover/internal/scenarios"
)

func withEnv(t *testing.T) *scenarios.Env {
	t.Helper()
	env, cleanup, err := scenarios.TempEnv(false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	return env
}

func TestBarrierRevocationThenLateReceipt(t *testing.T) {
	env := withEnv(t)
	res, err := scenarios.BarrierRevocationThenLateReceipt(env)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != model.OutcomeRejected || res.Reason != model.ReasonCustodianRevoked {
		t.Fatalf("late receipt outcome=%q reason=%q, want rejected/custodian_revoked", res.Outcome, res.Reason)
	}
	// The revocation was durable before the receipt was adjudicated, so the
	// recorded custody snapshot must say revoked.
	if res.Details["status"] != model.CustodyRevoked {
		t.Fatalf("details status = %q, want revoked", res.Details["status"])
	}
	rep, err := env.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("audit: %s", scenarios.Report(rep))
	}
	if rep.Rejected != 1 || rep.Accepted != 0 {
		t.Fatalf("audit: %s", scenarios.Report(rep))
	}
}

func TestBarrierCommittedButUnacknowledged(t *testing.T) {
	env := withEnv(t)
	rec, err := scenarios.BarrierCommittedButUnacknowledged(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Reconstructed) != 1 {
		t.Fatalf("reconstructed %d, want 1", len(rec.Reconstructed))
	}
	got := rec.Reconstructed[0]
	if got.Case != "CASE-CRASH" || got.Version != 1 {
		t.Fatalf("reconstructed %+v", got)
	}
	rep, err := env.Audit()
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("audit after recovery: %s", scenarios.Report(rep))
	}
	if rep.Recovered != 1 || rep.Accepted != 1 || rep.Attempts != 1 {
		t.Fatalf("audit after recovery: %s", scenarios.Report(rep))
	}
}

func TestRecoveryIsIdempotent(t *testing.T) {
	env := withEnv(t)
	if _, err := scenarios.BarrierCommittedButUnacknowledged(env); err != nil {
		t.Fatal(err)
	}
	// A second recovery must reconstruct nothing.
	if err := env.Close(); err != nil {
		t.Fatal(err)
	}
	_, rep2, err := scenarios.RecoverAgain(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep2.Reconstructed) != 0 {
		t.Fatalf("second recovery reconstructed %d attempts, want 0", len(rep2.Reconstructed))
	}
}
