// Package ledger implements the append-only closure-attachment handover book.
//
// A Ledger owns two hash-chained logs and one attachment pack per department:
//
//   - journal.jsonl     durable custody + accepted handovers (commit chain)
//   - reconciled.jsonl  self-sufficient audit log: genesis, custody mirror,
//                       and every adjudicated attempt
//   - packs/*.bin       the actual attachment bytes, self-describing
//
// The reconciliation log is deliberately self-sufficient: an independent
// verifier recomputes custody and every decision from it alone, and recovery
// repairs a crash from the journal plus the actual packs.
//
// Crash model: a handover is committed when both packs contain the bytes and
// its journal record is fsynced.  A crash after that point but before the
// reconciliation record and caller response is repaired by Recover, which
// reconstructs the missing attempt from the journal and the packs.
package ledger

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"handover/internal/model"
	"handover/internal/wire"
)

// ErrSimulatedCrash is returned by Submit when Config.CrashAfterJournalAccept
// is set: the commit is durable but the caller never observes a response.
var ErrSimulatedCrash = errors.New("ledger: simulated crash after durable commit")

// Signer is one control root's signing capability.  Tests own these; the ledger
// only ever sees the resulting model.Approval.
type Signer struct {
	Root string
	Dept model.TenantID
	Priv ed25519.PrivateKey
}

// Sign produces this root's approval over a binding.
func (s Signer) Sign(b model.ApprovalBinding) model.Approval {
	return model.Approval{
		Root: s.Root,
		Side: s.Dept,
		Sig:  ed25519.Sign(s.Priv, b.Bytes()),
	}
}

// Request is one handover submission.  Present distinguishes "no bytes
// supplied" from an intentionally empty attachment.
type Request struct {
	Envelope model.Envelope
	Payload  []byte
	Present  bool
}

// Config selects the on-disk directory, trusted roots and durability.
type Config struct {
	Dir     string
	Keyring *model.Keyring
	// Sync fsyncs after each durable write.  Crash scenarios enable it; bulk
	// benchmarks may disable it.
	Sync bool
	// CrashAfterJournalAccept models process death after the commit is durable
	// but before the reconciliation record and caller response.
	CrashAfterJournalAccept bool
}

// Result is the outcome of one Submit call.
type Result struct {
	RequestID  string
	Outcome    model.Outcome
	Reason     string
	Committed  uint64
	AttemptSeq uint64
	Details    map[string]string
}

// Ledger is a single-process handover book that is safe for concurrent use.
type Ledger struct {
	mu      sync.Mutex
	cfg     Config
	journal *wire.Log
	recon   *wire.Log
	packs   map[model.TenantID]*wire.Pack

	tenants []model.TenantID
	authGen uint64

	// Custody events in journal order.  journalSeq is the sequence of the
	// journal record that produced the event; every event is mirrored into the
	// reconciliation log so the audit log is self-sufficient.
	events []custodyEvent

	// Case version index built from committed journal accepts.
	cases map[model.CaseID]*caseState
	// Request IDs already adjudicated, to keep Recover idempotent.
	seenRequests map[string]bool
}

type custodyEvent struct {
	journalSeq uint64
	tenant     model.TenantID
	custodian  string
	grant      bool
	authGen    uint64
}

type caseState struct {
	versions map[uint64]acceptedVersion
}

type acceptedVersion struct {
	seq      uint64 // journal seq
	envelope model.Envelope
	refs     []model.SideRef
}

// Open opens or creates a ledger in cfg.Dir and replays its logs.
func Open(cfg Config) (*Ledger, error) {
	if cfg.Dir == "" {
		return nil, errors.New("ledger: empty dir")
	}
	if cfg.Keyring == nil {
		return nil, errors.New("ledger: nil keyring")
	}
	if err := os.MkdirAll(cfg.Dir, 0o755); err != nil {
		return nil, err
	}
	l := &Ledger{
		cfg:          cfg,
		packs:        make(map[model.TenantID]*wire.Pack),
		cases:        make(map[model.CaseID]*caseState),
		seenRequests: make(map[string]bool),
	}
	var err error
	l.journal, err = wire.OpenLog(filepath.Join(cfg.Dir, "journal.jsonl"), model.JournalDomain)
	if err != nil {
		return nil, err
	}
	l.recon, err = wire.OpenLog(filepath.Join(cfg.Dir, "reconciled.jsonl"), model.ReconDomain)
	if err != nil {
		return nil, err
	}
	if err := l.replay(); err != nil {
		return nil, err
	}
	return l, nil
}

// Close flushes and closes every file.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var first error
	note := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	note(l.journal.Close())
	note(l.recon.Close())
	for _, p := range l.packs {
		note(p.Close())
	}
	return first
}

// Dir returns the ledger directory.
func (l *Ledger) Dir() string { return l.cfg.Dir }

func (l *Ledger) replay() error {
	// The journal is authoritative for custody and commits; derive in-memory
	// state from it.  The reconciliation mirror is checked/repaired in Recover.
	for _, rec := range l.journal.Records() {
		switch rec.Type {
		case model.TypeGenesis:
			var g model.GenesisPayload
			if err := json.Unmarshal(rec.Payload, &g); err != nil {
				return err
			}
			for _, t := range g.Tenants {
				if !containsTenant(l.tenants, t) {
					l.tenants = append(l.tenants, t)
				}
			}
		case model.TypeGrant:
			var g model.GrantPayload
			if err := json.Unmarshal(rec.Payload, &g); err != nil {
				return err
			}
			l.applyMirror(model.MirrorPayload{
				Grant: true, Tenant: g.Tenant, Custodian: g.Custodian,
				AuthGen: g.AuthGen, JournalSeq: rec.Seq,
			})
		case model.TypeRevoke:
			var r model.RevokePayload
			if err := json.Unmarshal(rec.Payload, &r); err != nil {
				return err
			}
			l.applyMirror(model.MirrorPayload{
				Grant: false, Tenant: r.Tenant, Custodian: r.Custodian,
				AuthGen: r.AuthGen, JournalSeq: rec.Seq, Reason: r.Reason,
			})
		case model.TypeAccept:
			var a model.AcceptPayload
			if err := json.Unmarshal(rec.Payload, &a); err != nil {
				return err
			}
			l.indexAccepted(rec.Seq, a)
		}
	}
	// Learn already-recorded attempts (for Recover idempotence and duplicate
	// request tracking) from the reconciliation log.
	for _, rec := range l.recon.Records() {
		switch rec.Type {
		case model.ReconGenesis:
			var g model.GenesisPayload
			if err := json.Unmarshal(rec.Payload, &g); err != nil {
				return err
			}
			for _, t := range g.Tenants {
				if !containsTenant(l.tenants, t) {
					l.tenants = append(l.tenants, t)
				}
			}
		case model.ReconAttempt:
			var a model.AttemptPayload
			if err := json.Unmarshal(rec.Payload, &a); err != nil {
				return err
			}
			l.seenRequests[a.RequestID] = true
		}
	}
	// Packs can only be opened once genesis revealed the tenant set.
	for _, t := range l.tenants {
		p, err := wire.OpenPack(packPath(l.cfg.Dir, t), t)
		if err != nil {
			return err
		}
		l.packs[t] = p
	}
	return nil
}

func packPath(dir string, t model.TenantID) string {
	return filepath.Join(dir, "packs", "attachments-"+string(t)+".bin")
}

func (l *Ledger) applyMirror(m model.MirrorPayload) {
	if m.AuthGen > l.authGen {
		l.authGen = m.AuthGen
	}
	l.events = append(l.events, custodyEvent{
		journalSeq: m.JournalSeq,
		tenant:     m.Tenant,
		custodian:  m.Custodian,
		grant:      m.Grant,
		authGen:    m.AuthGen,
	})
}

func (l *Ledger) indexAccepted(seq uint64, acc model.AcceptPayload) {
	cs := l.cases[acc.Case]
	if cs == nil {
		cs = &caseState{versions: make(map[uint64]acceptedVersion)}
		l.cases[acc.Case] = cs
	}
	cs.versions[acc.Version] = acceptedVersion{seq: seq, envelope: acc.Envelope, refs: acc.Refs}
}

// Tenants returns the ledger's tenants in genesis order.
func (l *Ledger) Tenants() []model.TenantID { return append([]model.TenantID(nil), l.tenants...) }

// CurrentAuthGen returns the authorization generation in force.
func (l *Ledger) CurrentAuthGen() uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.authGen
}

// EnsureGenesis writes genesis and one grant per tenant when the ledger is
// empty.  Each grant advances the authorization generation, so after genesis the
// generation equals the number of tenants.  Journal and reconciliation log both
// receive the events.
func (l *Ledger) EnsureGenesis(ledgerID string, tenants []model.TenantID, custodians map[model.TenantID]string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.journal.Records()) > 0 {
		return nil
	}
	if len(tenants) < 2 {
		return errors.New("ledger: need at least two tenants")
	}
	gen := model.GenesisPayload{LedgerID: ledgerID, Tenants: tenants}
	if _, err := l.journal.Append(model.TypeGenesis, gen, l.cfg.Sync); err != nil {
		return err
	}
	if _, err := l.recon.Append(model.ReconGenesis, gen, l.cfg.Sync); err != nil {
		return err
	}
	for _, t := range tenants {
		if !containsTenant(l.tenants, t) {
			l.tenants = append(l.tenants, t)
		}
	}
	// Packs can only be opened once the tenant set is known.
	for _, t := range tenants {
		if l.packs[t] != nil {
			continue
		}
		p, err := wire.OpenPack(packPath(l.cfg.Dir, t), t)
		if err != nil {
			return err
		}
		l.packs[t] = p
	}
	for _, t := range tenants {
		cust := custodians[t]
		if cust == "" {
			return fmt.Errorf("ledger: tenant %q has no custodian", t)
		}
		if err := l.grantLocked(t, cust); err != nil {
			return err
		}
	}
	return nil
}

// Grant installs a new custodian for a tenant and advances the auth generation.
// The previous custodian is superseded and treated as revoked from that point.
func (l *Ledger) Grant(tenant model.TenantID, custodian string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !containsTenant(l.tenants, tenant) {
		return fmt.Errorf("ledger: unknown tenant %q", tenant)
	}
	if custodian == "" {
		return errors.New("ledger: empty custodian")
	}
	return l.grantLocked(tenant, custodian)
}

func (l *Ledger) grantLocked(tenant model.TenantID, custodian string) error {
	g := model.GrantPayload{Tenant: tenant, Custodian: custodian, AuthGen: l.authGen + 1}
	jrec, err := l.journal.Append(model.TypeGrant, g, l.cfg.Sync)
	if err != nil {
		return err
	}
	m := model.MirrorPayload{Grant: true, Tenant: tenant, Custodian: custodian, AuthGen: g.AuthGen, JournalSeq: jrec.Seq}
	if _, err := l.recon.Append(model.ReconGrant, m, l.cfg.Sync); err != nil {
		return err
	}
	l.applyMirror(m)
	return nil
}

// Revoke revokes the tenant's active custodian and advances the auth
// generation.  Both the journal and the reconciliation mirror are durable
// before Revoke returns, which the barrier scenario relies on.
func (l *Ledger) Revoke(tenant model.TenantID, custodian, reason string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !containsTenant(l.tenants, tenant) {
		return fmt.Errorf("ledger: unknown tenant %q", tenant)
	}
	if l.activeName(tenant) != custodian {
		return fmt.Errorf("ledger: %q is not the active custodian of %q", custodian, tenant)
	}
	r := model.RevokePayload{Tenant: tenant, Custodian: custodian, AuthGen: l.authGen + 1, Reason: reason}
	jrec, err := l.journal.Append(model.TypeRevoke, r, l.cfg.Sync)
	if err != nil {
		return err
	}
	m := model.MirrorPayload{Grant: false, Tenant: tenant, Custodian: custodian, AuthGen: r.AuthGen, JournalSeq: jrec.Seq, Reason: reason}
	if _, err := l.recon.Append(model.ReconRevoke, m, l.cfg.Sync); err != nil {
		return err
	}
	l.applyMirror(m)
	return nil
}

// activeName returns the tenant's active custodian, if any.
func (l *Ledger) activeName(tenant model.TenantID) string {
	active := ""
	for _, e := range l.events {
		if e.tenant != tenant {
			continue
		}
		if e.grant {
			active = e.custodian
		} else if active == e.custodian {
			active = ""
		}
	}
	return active
}

// Submit adjudicates one handover.
//
// Check order is deliberate:
//  1. Envelope shape and tenant sanity.
//  2. Attachment integrity (actual bytes vs claimed digest).
//  3. Version-level idempotency: same version + same digest + same tenants is a
//     duplicate; same version + different digest is a conflict.  This runs
//     before custody so a retransmission is classified as a retransmission even
//     if custody changed after the original commit.
//  4. Custody: a revoked or unknown custodian on either side rejects.
//  5. Authorization generation must be current.
//  6. Two distinct control roots must approve, binding digest, both tenants,
//     previous version and authorization generation.
//  7. Version sequencing, then commit.
func (l *Ledger) Submit(req Request) (Result, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	env := req.Envelope
	journalHead := l.journal.LastSeq()
	at := model.AttemptPayload{
		Envelope:              env,
		JournalHeadAtDecision: journalHead,
		GlobalAuthGen:         l.authGen,
		PrevAcceptedVersion:   l.maxVersionUpTo(env.Case, journalHead),
		FromCustody:           l.snapshotAt(journalHead, env.FromTenant, env.FromCustodian),
		ToCustody:             l.snapshotAt(journalHead, env.ToTenant, env.ToCustodian),
	}
	at.PayloadPresent = req.Present
	if req.Present {
		at.ActualDigest = model.DigestOf(req.Payload)
	}

	finish := func(out model.Outcome, reason string, details map[string]string, quarantined bool, refs []model.SideRef, committed uint64) (Result, error) {
		at.Outcome = out
		at.Reason = reason
		at.Details = details
		at.Quarantined = quarantined
		at.Refs = refs
		at.CommittedSeq = committed
		rec, err := l.recon.Append(model.ReconAttempt, at, l.cfg.Sync)
		if err != nil {
			return Result{}, err
		}
		l.seenRequests[env.RequestID] = true
		return Result{
			RequestID:  env.RequestID,
			Outcome:    out,
			Reason:     reason,
			Committed:  committed,
			AttemptSeq: rec.Seq,
			Details:    details,
		}, nil
	}
	reject := func(reason string, details map[string]string) (Result, error) {
		return finish(model.OutcomeRejected, reason, details, false, nil, 0)
	}

	// 1. Shape and tenants.
	if err := env.Binding().ValidateShape(); err != nil {
		return reject(model.ReasonBadBinding, map[string]string{"error": err.Error()})
	}
	if !containsTenant(l.tenants, env.FromTenant) || !containsTenant(l.tenants, env.ToTenant) {
		return reject(model.ReasonUnknownTenant, map[string]string{
			"from": string(env.FromTenant), "to": string(env.ToTenant),
		})
	}
	if l.authGen == 0 {
		return reject(model.ReasonStaleAuthGen, map[string]string{"error": "ledger has no authorization generation"})
	}

	// 2. Attachment integrity.
	if !req.Present {
		return reject(model.ReasonMissingPayload, nil)
	}
	actual := model.DigestOf(req.Payload)
	if actual != env.Digest {
		qref, qerr := l.quarantine(env.FromTenant, env, req.Payload)
		if qerr != nil {
			return Result{}, qerr
		}
		return finish(model.OutcomeRejected, model.ReasonDigestMismatch,
			map[string]string{"claimed": env.Digest.String(), "actual": actual.String()},
			true, []model.SideRef{qref}, 0)
	}

	// 3. Version-level idempotency, before custody.
	if cs := l.cases[env.Case]; cs != nil {
		if prev, ok := cs.versions[env.Version]; ok {
			sameTenants := prev.envelope.FromTenant == env.FromTenant && prev.envelope.ToTenant == env.ToTenant
			if prev.envelope.Digest == env.Digest && sameTenants {
				return finish(model.OutcomeDuplicate, "",
					map[string]string{"committed_seq": fmt.Sprint(prev.seq)}, false, prev.refs, prev.seq)
			}
			qref, qerr := l.quarantine(env.FromTenant, env, req.Payload)
			if qerr != nil {
				return Result{}, qerr
			}
			return finish(model.OutcomeConflict, "",
				map[string]string{
					"retained_digest":    prev.envelope.Digest.String(),
					"conflicting_digest": env.Digest.String(),
					"retained_seq":       fmt.Sprint(prev.seq),
				}, true, []model.SideRef{qref}, 0)
		}
	}

	// 4. Custody.
	if at.FromCustody.Status != model.CustodyActive {
		return reject(custodyReason(at.FromCustody.Status), custodyDetails(at.FromCustody))
	}
	if at.ToCustody.Status != model.CustodyActive {
		return reject(custodyReason(at.ToCustody.Status), custodyDetails(at.ToCustody))
	}

	// 5. Authorization generation.
	if env.AuthGen != l.authGen {
		return reject(model.ReasonStaleAuthGen, map[string]string{
			"presented": fmt.Sprint(env.AuthGen), "current": fmt.Sprint(l.authGen),
		})
	}

	// 6. Approvals: two distinct roots, one per side, same binding.
	if err := l.cfg.Keyring.VerifyApprovalSet(env.Binding(), env.Approvals); err != nil {
		return reject(model.ReasonBadApproval, map[string]string{"error": err.Error()})
	}

	// 7. Version sequencing.
	if env.Version > at.PrevAcceptedVersion+1 {
		return reject(model.ReasonVersionGap, map[string]string{
			"presented": fmt.Sprint(env.Version), "expected": fmt.Sprint(at.PrevAcceptedVersion + 1),
		})
	}
	if env.PrevVersion != at.PrevAcceptedVersion {
		return reject(model.ReasonStalePrevious, map[string]string{
			"presented": fmt.Sprint(env.PrevVersion), "expected": fmt.Sprint(at.PrevAcceptedVersion),
		})
	}

	// Commit: both packs first, then the journal, then the reconciliation log.
	refFrom, err := l.writePack(env.FromTenant, env, req.Payload)
	if err != nil {
		return Result{}, err
	}
	refTo, err := l.writePack(env.ToTenant, env, req.Payload)
	if err != nil {
		return Result{}, err
	}
	refs := []model.SideRef{refFrom, refTo}
	sortRefs(refs)

	acc := model.AcceptPayload{Envelope: env, Refs: refs}
	accRec, err := l.journal.Append(model.TypeAccept, acc, l.cfg.Sync)
	if err != nil {
		return Result{}, err
	}
	l.indexAccepted(accRec.Seq, acc)

	if l.cfg.CrashAfterJournalAccept {
		return Result{}, ErrSimulatedCrash
	}

	at.Refs = refs
	at.CommittedSeq = accRec.Seq
	at.Outcome = model.OutcomeAccepted
	rec, err := l.recon.Append(model.ReconAttempt, at, l.cfg.Sync)
	if err != nil {
		return Result{}, err
	}
	l.seenRequests[env.RequestID] = true
	return Result{
		RequestID:  env.RequestID,
		Outcome:    model.OutcomeAccepted,
		Committed:  accRec.Seq,
		AttemptSeq: rec.Seq,
	}, nil
}

func (l *Ledger) maxVersionUpTo(c model.CaseID, upTo uint64) uint64 {
	cs := l.cases[c]
	if cs == nil {
		return 0
	}
	var max uint64
	for v, av := range cs.versions {
		if av.seq <= upTo && v > max {
			max = v
		}
	}
	return max
}

func (l *Ledger) writePack(t model.TenantID, env model.Envelope, payload []byte) (model.SideRef, error) {
	p := l.packs[t]
	if p == nil {
		return model.SideRef{}, fmt.Errorf("ledger: no pack for tenant %q", t)
	}
	_, ref, err := p.Append(env.Meta(), payload, l.cfg.Sync)
	return ref, err
}

// quarantine stores rejected-but-noteworthy bytes in the sender's pack.  They
// are never referenced by a journal accept; the reconciliation record points at
// them explicitly so audit can tell them apart from committed bytes.
func (l *Ledger) quarantine(t model.TenantID, env model.Envelope, payload []byte) (model.SideRef, error) {
	p := l.packs[t]
	if p == nil {
		return model.SideRef{}, fmt.Errorf("ledger: no pack for tenant %q", t)
	}
	meta := env.Meta()
	meta.Digest = model.DigestOf(payload)
	_, ref, err := p.Append(meta, payload, l.cfg.Sync)
	return ref, err
}

// authGenAt returns the authorization generation in force at a journal head.
func (l *Ledger) authGenAt(head uint64) uint64 {
	var gen uint64
	for _, e := range l.events {
		if e.journalSeq <= head && e.authGen > gen {
			gen = e.authGen
		}
	}
	return gen
}

// snapshotAt recomputes one custodian's custody from custody events with
// journal sequence up to and including head.
func (l *Ledger) snapshotAt(head uint64, t model.TenantID, custodian string) model.CustodySnapshot {
	active := ""
	granted := false
	var revokedAt uint64
	for _, e := range l.events {
		if e.journalSeq > head || e.tenant != t {
			continue
		}
		if e.grant {
			if e.custodian == custodian {
				granted = true
				revokedAt = 0
			}
			active = e.custodian
		} else {
			if e.custodian == custodian && revokedAt == 0 {
				revokedAt = e.journalSeq
			}
			if active == e.custodian {
				active = ""
			}
		}
	}
	snap := model.CustodySnapshot{Tenant: t, Custodian: custodian}
	switch {
	case !granted:
		snap.Status = model.CustodyUnknown
	case active == custodian && revokedAt == 0:
		snap.Status = model.CustodyActive
	default:
		snap.Status = model.CustodyRevoked
		snap.RevokeSeq = revokedAt
	}
	return snap
}

func custodyReason(status string) string {
	if status == model.CustodyRevoked {
		return model.ReasonCustodianRevoked
	}
	return model.ReasonCustodianUnknown
}

func custodyDetails(s model.CustodySnapshot) map[string]string {
	d := map[string]string{
		"tenant":    string(s.Tenant),
		"custodian": s.Custodian,
		"status":    s.Status,
	}
	if s.RevokeSeq != 0 {
		d["revoke_seq"] = fmt.Sprint(s.RevokeSeq)
	}
	return d
}

func containsTenant(list []model.TenantID, t model.TenantID) bool {
	for _, x := range list {
		if x == t {
			return true
		}
	}
	return false
}

func sortRefs(refs []model.SideRef) {
	sort.Slice(refs, func(i, j int) bool { return refs[i].Tenant < refs[j].Tenant })
}
