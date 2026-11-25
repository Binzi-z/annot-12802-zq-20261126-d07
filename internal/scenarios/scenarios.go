// Package scenarios contains the executable handover scenarios shared by the
// unit tests and the cmd/selfcheck runner.  It deliberately does not import
// "testing"; callers supply a directory and interpret the returned error.
package scenarios

import (
	"fmt"
	"os"

	"handover/internal/audit"
	"handover/internal/fixture"
	"handover/internal/ledger"
	"handover/internal/model"
)

// Env is a fresh ledger plus its fixture world.
type Env struct {
	L   *ledger.Ledger
	W   *fixture.World
	Dir string
}

// NewEnv opens a fresh ledger in dir (creating it) and seeds genesis.
func NewEnv(dir string, sync bool) (*Env, error) {
	w, err := fixture.NewWorld()
	if err != nil {
		return nil, err
	}
	l, err := ledger.Open(ledger.Config{Dir: dir, Keyring: w.Keyring, Sync: sync})
	if err != nil {
		return nil, err
	}
	if err := l.EnsureGenesis("LEDGER-SCENARIO",
		fixture.SortedTenants(w.TenantA, w.TenantB), w.GenesisCustodians()); err != nil {
		l.Close()
		return nil, err
	}
	return &Env{L: l, W: w, Dir: dir}, nil
}

// TempEnv opens an environment in a fresh temp dir and returns a cleanup func.
func TempEnv(sync bool) (*Env, func(), error) {
	dir, err := os.MkdirTemp("", "handover-")
	if err != nil {
		return nil, nil, err
	}
	env, err := NewEnv(dir, sync)
	if err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}
	return env, func() { env.Close() }, nil
}

// Close closes the ledger.
func (e *Env) Close() error { return e.L.Close() }

// V1 builds and submits a valid first-version handover from DEPT-A to DEPT-B.
func (e *Env) V1(caseID model.CaseID, salt uint64) (ledger.Result, ledger.Request, error) {
	return e.Submit(caseID, 1, 0, salt, e.W.TenantA, e.W.TenantB, "CUST-A1", "CUST-B1", e.L.CurrentAuthGen())
}

// Submit builds a signed request against the given generation and submits it.
func (e *Env) Submit(caseID model.CaseID, version, prev, salt uint64,
	from, to model.TenantID, fromCust, toCust string, authGen uint64) (ledger.Result, ledger.Request, error) {
	payload := fixture.Payload(caseID, version, salt)
	req, err := e.W.SignedRequest(caseID, payload, from, to, fromCust, toCust, prev, version, authGen)
	if err != nil {
		return ledger.Result{}, ledger.Request{}, err
	}
	res, err := e.L.Submit(req)
	return res, req, err
}

// SubmitPayload submits caller-chosen bytes (for digest-mismatch tests).
func (e *Env) SubmitPayload(caseID model.CaseID, version, prev uint64, payload []byte,
	from, to model.TenantID, fromCust, toCust string, authGen uint64) (ledger.Result, error) {
	req, err := e.W.SignedRequest(caseID, payload, from, to, fromCust, toCust, prev, version, authGen)
	if err != nil {
		return ledger.Result{}, err
	}
	return e.L.Submit(req)
}

// Audit runs the independent verifier over the environment's directory.
func (e *Env) Audit() (*audit.Report, error) { return audit.Verify(e.Dir, e.W.Keyring) }

// Report renders an audit report compactly.
func Report(rep *audit.Report) string {
	s := fmt.Sprintf("attempts=%d accepted=%d dup=%d conflict=%d rejected=%d recovered=%d problems=%d",
		rep.Attempts, rep.Accepted, rep.Duplicates, rep.Conflicts, rep.Rejected, rep.Recovered, len(rep.Problems))
	for _, p := range rep.Problems {
		s += "\n  " + p.String()
	}
	return s
}
