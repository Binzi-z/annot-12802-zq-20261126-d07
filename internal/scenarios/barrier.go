package scenarios

import (
	"errors"
	"fmt"
	"sync"

	"handover/internal/fixture"
	"handover/internal/ledger"
)

// Rendezvous is a reusable counting barrier for the two-thread replays.  Each
// Wait blocks until all n parties have reached the same round.
type Rendezvous struct {
	mu    sync.Mutex
	cond  *sync.Cond
	n     int
	count int
	round int
}

// NewRendezvous makes a reusable n-party barrier.
func NewRendezvous(n int) *Rendezvous {
	r := &Rendezvous{n: n}
	r.cond = sync.NewCond(&r.mu)
	return r
}

// Wait blocks until all parties have reached this round.
func (r *Rendezvous) Wait() {
	r.mu.Lock()
	defer r.mu.Unlock()
	round := r.round
	r.count++
	if r.count == r.n {
		r.count = 0
		r.round++
		r.cond.Broadcast()
		return
	}
	for round == r.round {
		r.cond.Wait()
	}
}

// BarrierRevocationThenLateReceipt replays the "revocation already persisted
// while the handover receipt is still in flight" interleaving.
//
// Thread R: revokes DEPT-A's custodian (durable).
// Thread H: submitted a handover naming the now-revoked custodian and is about
// to record its receipt.
//
// A rendezvous forces R's revocation to land before H's receipt is adjudicated,
// so the receipt must be rejected as custodian_revoked, and the audit must
// confirm the rejection is explainable from custody at the recorded head.
func BarrierRevocationThenLateReceipt(env *Env) (*ledger.Result, error) {
	// Prepare the in-flight handover before the race so both threads are ready.
	handover := func() (ledger.Result, error) {
		res, _, err := env.Submit("CASE-LATE", 1, 0, 11, env.W.TenantA, env.W.TenantB,
			"CUST-A1", "CUST-B1", env.L.CurrentAuthGen())
		return res, err
	}

	rz := NewRendezvous(2)
	var (
		wg            sync.WaitGroup
		revokeErr     error
		handoverRes   ledger.Result
		handoverErr   error
	)

	wg.Add(2)
	go func() {
		defer wg.Done()
		rz.Wait() // both threads armed
		revokeErr = env.L.Revoke(env.W.TenantA, "CUST-A1", "revoked-while-in-flight")
		rz.Wait() // signal revocation durable
	}()
	go func() {
		defer wg.Done()
		rz.Wait() // both threads armed
		rz.Wait() // wait until revocation lands
		handoverRes, handoverErr = handover()
	}()
	wg.Wait()

	if revokeErr != nil {
		return nil, fmt.Errorf("revoke: %w", revokeErr)
	}
	if handoverErr != nil {
		return nil, fmt.Errorf("late handover: %w", handoverErr)
	}
	return &handoverRes, nil
}

// BarrierCommittedButUnacknowledged replays the "committed in the journal but the
// caller never received a response" crash, then recovers.
//
// The ledger is configured to die right after the durable journal commit.  A
// fresh process re-opens the directory; Recover must reconstruct the missing
// reconciliation record from the actual attachments and the journal, and the
// independent audit must then confirm every attempt and every byte.
func BarrierCommittedButUnacknowledged(env *Env) (*ledger.RecoveryReport, error) {
	// Arm the crash on the live ledger.
	crashCfg := ledger.Config{Dir: env.Dir, Keyring: env.W.Keyring, Sync: true, CrashAfterJournalAccept: true}
	crashed, err := ledger.Open(crashCfg)
	if err != nil {
		return nil, err
	}
	payload := fixture.Payload("CASE-CRASH", 1, 1)
	req, err := env.W.SignedRequest("CASE-CRASH", payload, env.W.TenantA, env.W.TenantB,
		"CUST-A1", "CUST-B1", 0, 1, crashed.CurrentAuthGen())
	if err != nil {
		crashed.Close()
		return nil, err
	}
	_, submitErr := crashed.Submit(req)
	if !errors.Is(submitErr, ledger.ErrSimulatedCrash) {
		crashed.Close()
		return nil, fmt.Errorf("expected simulated crash, got %v", submitErr)
	}
	// The process "died": close without a reconciliation record for this commit.
	crashed.Close()

	// New process recovers.
	recovered, rep, err := ledger.Recover(ledger.Config{Dir: env.Dir, Keyring: env.W.Keyring, Sync: true})
	if err != nil {
		return nil, err
	}
	env.L = recovered
	return rep, nil
}

// RecoverAgain re-runs recovery on an already-recovered environment, to prove
// the repair is idempotent.
func RecoverAgain(env *Env) (*ledger.Ledger, *ledger.RecoveryReport, error) {
	l, rep, err := ledger.Recover(ledger.Config{Dir: env.Dir, Keyring: env.W.Keyring, Sync: true})
	if err == nil {
		env.L = l
	}
	return l, rep, err
}
