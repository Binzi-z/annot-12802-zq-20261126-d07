// Package exhaustive checks the handover policy by brute force over every short
// interleaving of a small operation sequence.
//
// Two independent interpreters run each operation sequence:
//
//   - the real ledger, driven through its public API;
//   - a from-scratch reference model written here, which re-implements custody,
//     the version baseline and the documented check order.
//
// For every permutation of the operations the two must agree on each outcome and
// reason, and the independent audit must accept the resulting directory.  Because
// the enumeration is finite and short, this catches ordering bugs (e.g. custody
// checked before idempotency) that a single hand-written test can miss.
package exhaustive

import (
	"fmt"

	"handover/internal/fixture"
	"handover/internal/ledger"
	"handover/internal/model"
)

// Kind is an operation kind.
type Kind string

const (
	KindGrant  Kind = "grant"
	KindRevoke Kind = "revoke"
	KindSubmit Kind = "submit"
)

// Op is one atomic operation.  A submit carries the exact envelope it presents,
// including the authorization generation it was signed for, so both interpreters
// see identical inputs.
type Op struct {
	Kind     Kind
	Tenant   model.TenantID // grant/revoke target
	Custodian string        // grant: new name; revoke: name to revoke

	// Submit fields.
	Case     model.CaseID
	Version  uint64
	Prev     uint64
	Salt     uint64
	AuthGen  uint64
	FromCust string
	ToCust   string
}

func (o Op) String() string {
	switch o.Kind {
	case KindGrant:
		return fmt.Sprintf("grant(%s=%s)", o.Tenant, o.Custodian)
	case KindRevoke:
		return fmt.Sprintf("revoke(%s=%s)", o.Tenant, o.Custodian)
	default:
		return fmt.Sprintf("submit(%s v%d prev%d salt%d gen%d)", o.Case, o.Version, o.Prev, o.Salt, o.AuthGen)
	}
}

// Outcome is the expected result of one operation.
type Outcome struct {
	Outcome model.Outcome
	Reason  string
	// AcceptedVersion is set when a submit commits.
	Committed bool
}

// Permutations returns every ordering of ops in a stable, deterministic order.
func Permutations(ops []Op) [][]Op {
	idx := make([]int, len(ops))
	for i := range idx {
		idx[i] = i
	}
	var out [][]Op
	var rec func(k int)
	rec = func(k int) {
		if k == len(idx) {
			perm := make([]Op, len(idx))
			for i, j := range idx {
				perm[i] = ops[j]
			}
			out = append(out, perm)
			return
		}
		for i := k; i < len(idx); i++ {
			idx[k], idx[i] = idx[i], idx[k]
			rec(k + 1)
			idx[k], idx[i] = idx[i], idx[k]
		}
	}
	rec(0)
	return out
}

// RunReal executes the operations against a fresh ledger and returns each
// outcome.  The ledger must already be opened and seeded.
func RunReal(l *ledger.Ledger, w *fixture.World, ops []Op) ([]Outcome, error) {
	out := make([]Outcome, len(ops))
	for i, op := range ops {
		switch op.Kind {
		case KindGrant:
			if err := l.Grant(op.Tenant, op.Custodian); err != nil {
				return nil, fmt.Errorf("op %d %s: %w", i, op, err)
			}
			out[i] = Outcome{Outcome: "ok"}
		case KindRevoke:
			if err := l.Revoke(op.Tenant, op.Custodian, "exhaustive"); err != nil {
				return nil, fmt.Errorf("op %d %s: %w", i, op, err)
			}
			out[i] = Outcome{Outcome: "ok"}
		case KindSubmit:
			payload := fixture.Payload(op.Case, op.Version, op.Salt)
			req, err := w.SignedRequest(op.Case, payload, w.TenantA, w.TenantB,
				op.FromCust, op.ToCust, op.Prev, op.Version, op.AuthGen)
			if err != nil {
				return nil, err
			}
			res, err := l.Submit(req)
			if err != nil {
				return nil, fmt.Errorf("op %d %s: %w", i, op, err)
			}
			out[i] = Outcome{Outcome: res.Outcome, Reason: res.Reason, Committed: res.Outcome == model.OutcomeAccepted}
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Reference model: an independent re-implementation of the policy.

// modelState is the reference state.
type modelState struct {
	tenants []model.TenantID
	authGen uint64
	// per tenant: lifecycle of each custodian and the active name.
	lifecycle map[model.TenantID]map[string]*life
	active    map[model.TenantID]string
	// per case: highest committed version and the digest committed per version.
	maxVersion map[model.CaseID]uint64
	digest     map[model.CaseID]map[uint64]model.Digest
	fromTo     map[model.CaseID]map[uint64][2]model.TenantID
}

type life struct {
	granted   bool
	revoked   bool
	revokeSeq int
}

// Ref is the reference interpreter.  It needs the keyring only for the
// cryptographic signature check, which is not policy.
type Ref struct {
	w     *fixture.World
	state *modelState
	seq   int
}

// NewRef builds a reference model matching a freshly seeded ledger: each tenant
// has its genesis custodian with a generation bumped once per grant.
func NewRef(w *fixture.World) *Ref {
	st := &modelState{
		tenants:    fixture.SortedTenants(w.TenantA, w.TenantB),
		authGen:    0,
		lifecycle:  make(map[model.TenantID]map[string]*life),
		active:     make(map[model.TenantID]string),
		maxVersion: make(map[model.CaseID]uint64),
		digest:     make(map[model.CaseID]map[uint64]model.Digest),
		fromTo:     make(map[model.CaseID]map[uint64][2]model.TenantID),
	}
	r := &Ref{w: w, state: st}
	gen := w.GenesisCustodians()
	for _, t := range st.tenants {
		r.grant(t, gen[t])
	}
	return r
}

func (r *Ref) life(t model.TenantID, name string) *life {
	if r.state.lifecycle[t] == nil {
		r.state.lifecycle[t] = make(map[string]*life)
	}
	l := r.state.lifecycle[t][name]
	if l == nil {
		l = &life{}
		r.state.lifecycle[t][name] = l
	}
	return l
}

func (r *Ref) grant(t model.TenantID, name string) {
	r.seq++
	r.state.authGen++
	if old := r.state.active[t]; old != "" && old != name {
		if lc := r.life(t, old); !lc.revoked {
			lc.revoked = true
			lc.revokeSeq = r.seq
		}
	}
	lc := r.life(t, name)
	lc.granted = true
	lc.revoked = false
	lc.revokeSeq = 0
	r.state.active[t] = name
}

func (r *Ref) revoke(t model.TenantID, name string) {
	r.seq++
	r.state.authGen++
	lc := r.life(t, name)
	lc.revoked = true
	lc.revokeSeq = r.seq
	if r.state.active[t] == name {
		delete(r.state.active, t)
	}
}

func (r *Ref) snapshot(t model.TenantID, name string) model.CustodySnapshot {
	lc := r.state.lifecycle[t][name]
	snap := model.CustodySnapshot{Tenant: t, Custodian: name}
	switch {
	case lc == nil || !lc.granted:
		snap.Status = model.CustodyUnknown
	case r.state.active[t] == name && !lc.revoked:
		snap.Status = model.CustodyActive
	default:
		snap.Status = model.CustodyRevoked
	}
	return snap
}

// Apply interprets one operation and returns the expected outcome.
func (r *Ref) Apply(op Op) Outcome {
	switch op.Kind {
	case KindGrant:
		r.grant(op.Tenant, op.Custodian)
		return Outcome{Outcome: "ok"}
	case KindRevoke:
		r.revoke(op.Tenant, op.Custodian)
		return Outcome{Outcome: "ok"}
	default:
		return r.submit(op)
	}
}

func (r *Ref) submit(op Op) Outcome {
	from := r.snapshot(r.w.TenantA, op.FromCust)
	to := r.snapshot(r.w.TenantB, op.ToCust)
	payload := fixture.Payload(op.Case, op.Version, op.Salt)
	digest := model.DigestOf(payload)

	// Policy order must match the ledger's documented order.
	if op.Version == 0 || from.Tenant == to.Tenant {
		return Outcome{Outcome: model.OutcomeRejected, Reason: model.ReasonBadBinding}
	}
	// Version-level idempotency.
	if versions, ok := r.state.digest[op.Case]; ok {
		if prevDigest, committed := versions[op.Version]; committed {
			ft := r.state.fromTo[op.Case][op.Version]
			if prevDigest == digest && ft[0] == r.w.TenantA && ft[1] == r.w.TenantB {
				return Outcome{Outcome: model.OutcomeDuplicate}
			}
			return Outcome{Outcome: model.OutcomeConflict}
		}
	}
	// Custody.
	if from.Status != model.CustodyActive {
		return Outcome{Outcome: model.OutcomeRejected, Reason: custodyReason(from.Status)}
	}
	if to.Status != model.CustodyActive {
		return Outcome{Outcome: model.OutcomeRejected, Reason: custodyReason(to.Status)}
	}
	// Authorization generation.
	if op.AuthGen != r.state.authGen {
		return Outcome{Outcome: model.OutcomeRejected, Reason: model.ReasonStaleAuthGen}
	}
	// Approvals (cryptographic; the reference signs exactly what it checks).
	b := model.ApprovalBinding{
		Case: op.Case, Digest: digest, FromTenant: r.w.TenantA, ToTenant: r.w.TenantB,
		PrevVersion: op.Prev, Version: op.Version, AuthGen: op.AuthGen,
	}
	appr := []model.Approval{
		r.w.Signers()[r.w.TenantA].Sign(b),
		r.w.Signers()[r.w.TenantB].Sign(b),
	}
	if err := r.w.Keyring.VerifyApprovalSet(b, appr); err != nil {
		return Outcome{Outcome: model.OutcomeRejected, Reason: model.ReasonBadApproval}
	}
	// Version sequencing.
	baseline := r.state.maxVersion[op.Case]
	if op.Version > baseline+1 {
		return Outcome{Outcome: model.OutcomeRejected, Reason: model.ReasonVersionGap}
	}
	if op.Prev != baseline {
		return Outcome{Outcome: model.OutcomeRejected, Reason: model.ReasonStalePrevious}
	}
	// Accept.
	if r.state.digest[op.Case] == nil {
		r.state.digest[op.Case] = make(map[uint64]model.Digest)
		r.state.fromTo[op.Case] = make(map[uint64][2]model.TenantID)
	}
	r.state.digest[op.Case][op.Version] = digest
	r.state.fromTo[op.Case][op.Version] = [2]model.TenantID{r.w.TenantA, r.w.TenantB}
	r.state.maxVersion[op.Case] = op.Version
	return Outcome{Outcome: model.OutcomeAccepted, Committed: true}
}

func custodyReason(status string) string {
	if status == model.CustodyRevoked {
		return model.ReasonCustodianRevoked
	}
	return model.ReasonCustodianUnknown
}
