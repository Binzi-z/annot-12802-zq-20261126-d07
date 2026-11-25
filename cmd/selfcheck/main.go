// Command selfcheck runs the handover scenarios end-to-end and prints results.
// It is the runnable twin of the tests: every check it performs is also asserted
// by a *_test.go file, but selfcheck needs no test harness so it can run in
// restricted environments.
package main

import (
	"fmt"
	"os"

	"handover/internal/model"
	"handover/internal/scenarios"
)

type check struct {
	name string
	run  func() error
}

func main() {
	checks := []check{
		{"accept+audit", checkAccept},
		{"duplicate-vs-conflict", checkDuplicateVsConflict},
		{"revoked-custodian", checkRevoked},
		{"barrier-revocation-late-receipt", checkBarrierRevocation},
		{"barrier-committed-unacknowledged", checkBarrierCrash},
	}
	failed := 0
	for _, c := range checks {
		if err := c.run(); err != nil {
			fmt.Printf("FAIL %-40s %v\n", c.name, err)
			failed++
			continue
		}
		fmt.Printf("ok   %s\n", c.name)
	}
	if failed > 0 {
		fmt.Printf("\n%d check(s) failed\n", failed)
		os.Exit(1)
	}
	fmt.Println("\nall checks passed")
}

func withEnv(fn func(env *scenarios.Env) error) error {
	env, cleanup, err := scenarios.TempEnv(false)
	if err != nil {
		return err
	}
	defer cleanup()
	return fn(env)
}

func checkAccept() error {
	return withEnv(func(env *scenarios.Env) error {
		res, _, err := env.V1("CASE-1", 7)
		if err != nil {
			return err
		}
		if res.Outcome != model.OutcomeAccepted {
			return fmt.Errorf("outcome %q (%s)", res.Outcome, res.Reason)
		}
		rep, err := env.Audit()
		if err != nil {
			return err
		}
		if !rep.OK() {
			return fmt.Errorf("audit: %s", scenarios.Report(rep))
		}
		return nil
	})
}

func checkDuplicateVsConflict() error {
	return withEnv(func(env *scenarios.Env) error {
		first, req, err := env.V1("CASE-DUP", 3)
		if err != nil {
			return err
		}
		if first.Outcome != model.OutcomeAccepted {
			return fmt.Errorf("first %q", first.Outcome)
		}
		// Same bytes again -> duplicate.
		dup, err := env.L.Submit(req)
		if err != nil {
			return err
		}
		if dup.Outcome != model.OutcomeDuplicate {
			return fmt.Errorf("retransmit outcome %q (%s), want duplicate", dup.Outcome, dup.Reason)
		}
		// Different bytes, same version -> conflict.
		conf, err := env.SubmitPayload("CASE-DUP", 1, 0, []byte("different payload"), env.W.TenantA, env.W.TenantB, "CUST-A1", "CUST-B1", env.L.CurrentAuthGen())
		if err != nil {
			return err
		}
		if conf.Outcome != model.OutcomeConflict {
			return fmt.Errorf("same-version-different-digest outcome %q (%s), want conflict", conf.Outcome, conf.Reason)
		}
		rep, err := env.Audit()
		if err != nil {
			return err
		}
		if !rep.OK() {
			return fmt.Errorf("audit: %s", scenarios.Report(rep))
		}
		if rep.Duplicates != 1 || rep.Conflicts != 1 || rep.Accepted != 1 {
			return fmt.Errorf("counts: %s", scenarios.Report(rep))
		}
		return nil
	})
}

func checkRevoked() error {
	return withEnv(func(env *scenarios.Env) error {
		if err := env.L.Revoke(env.W.TenantA, "CUST-A1", "offboarding"); err != nil {
			return err
		}
		res, _, err := env.Submit("CASE-REV", 1, 0, 1, env.W.TenantA, env.W.TenantB, "CUST-A1", "CUST-B1", env.L.CurrentAuthGen())
		if err != nil {
			return err
		}
		if res.Outcome != model.OutcomeRejected || res.Reason != model.ReasonCustodianRevoked {
			return fmt.Errorf("outcome=%q reason=%q, want rejected/custodian_revoked", res.Outcome, res.Reason)
		}
		rep, err := env.Audit()
		if err != nil {
			return err
		}
		if !rep.OK() {
			return fmt.Errorf("audit: %s", scenarios.Report(rep))
		}
		return nil
	})
}

func checkBarrierRevocation() error {
	return withEnv(func(env *scenarios.Env) error {
		res, err := scenarios.BarrierRevocationThenLateReceipt(env)
		if err != nil {
			return err
		}
		if res.Outcome != model.OutcomeRejected || res.Reason != model.ReasonCustodianRevoked {
			return fmt.Errorf("late receipt outcome=%q reason=%q, want rejected/custodian_revoked", res.Outcome, res.Reason)
		}
		rep, err := env.Audit()
		if err != nil {
			return err
		}
		if !rep.OK() {
			return fmt.Errorf("audit: %s", scenarios.Report(rep))
		}
		return nil
	})
}

func checkBarrierCrash() error {
	return withEnv(func(env *scenarios.Env) error {
		rep, err := scenarios.BarrierCommittedButUnacknowledged(env)
		if err != nil {
			return err
		}
		if len(rep.Reconstructed) != 1 {
			return fmt.Errorf("reconstructed %d attempts, want 1", len(rep.Reconstructed))
		}
		ar, err := env.Audit()
		if err != nil {
			return err
		}
		if !ar.OK() {
			return fmt.Errorf("audit after recovery: %s", scenarios.Report(ar))
		}
		if ar.Recovered != 1 || ar.Accepted != 1 {
			return fmt.Errorf("audit counts after recovery: %s", scenarios.Report(ar))
		}
		return nil
	})
}
