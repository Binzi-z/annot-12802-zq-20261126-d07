package model

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
)

// Domain separators for the two hash-chained logs.  Keeping them distinct means
// a record cannot be replayed from the reconciliation log into the journal.
const (
	JournalDomain = "handover-journal-v1\x00"
	ReconDomain   = "handover-recon-v1\x00"
)

// ChainHash hashes one log record.  seq is the record's sequence number, typ is
// its tag and payload is the exact serialized payload.  The previous hash links
// records into a tamper-evident chain.
func ChainHash(domain string, prev Digest, seq uint64, typ string, payload []byte) Digest {
	h := sha256.New()
	h.Write([]byte(domain))
	h.Write(prev[:])
	var num [8]byte
	binary.BigEndian.PutUint64(num[:], seq)
	h.Write(num[:])
	binary.BigEndian.PutUint64(num[:], uint64(len(typ)))
	h.Write(num[:])
	h.Write([]byte(typ))
	binary.BigEndian.PutUint64(num[:], uint64(len(payload)))
	h.Write(num[:])
	h.Write(payload)
	var out Digest
	copy(out[:], h.Sum(nil))
	return out
}

// Record is one line of either log.  Payload is kept raw so the verifier can
// re-hash exactly what was written.
type Record struct {
	Seq     uint64          `json:"seq"`
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
	Prev    Digest          `json:"prev"`
	Hash    Digest          `json:"hash"`
}

// MakeRecord builds a chained record for the given domain.
func MakeRecord(domain string, prev Digest, seq uint64, typ string, payload interface{}) (Record, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Record{}, err
	}
	return Record{
		Seq:     seq,
		Type:    typ,
		Payload: raw,
		Prev:    prev,
		Hash:    ChainHash(domain, prev, seq, typ, raw),
	}, nil
}

// VerifyChain recomputes the record hash and checks the previous link.
func VerifyChain(domain string, rec Record, wantPrev Digest) error {
	if rec.Prev != wantPrev {
		return fmt.Errorf("record %d: prev %s, want %s", rec.Seq, rec.Prev, wantPrev)
	}
	got := ChainHash(domain, rec.Prev, rec.Seq, rec.Type, rec.Payload)
	if got != rec.Hash {
		return fmt.Errorf("record %d: hash %s, want %s", rec.Seq, rec.Hash, got)
	}
	return nil
}

// Journal record types.
const (
	TypeGenesis = "genesis"
	TypeGrant   = "custodian.grant"
	TypeRevoke  = "custodian.revoke"
	TypeAccept  = "handover.accept"
)

// Reconciliation (audit) log record types.  The reconciliation log mirrors
// genesis and every custody change so it is self-sufficient: recovery and
// independent recomputation never need the journal.
const (
	ReconGenesis = "ledger.genesis"
	ReconGrant   = "custody.grant"
	ReconRevoke  = "custody.revoke"
	ReconAttempt = "attempt"
)

// GenesisPayload is the first journal and reconciliation record.
type GenesisPayload struct {
	LedgerID string     `json:"ledger_id"`
	Tenants  []TenantID `json:"tenants"`
}

// GrantPayload installs a custodian and advances the authorization generation.
type GrantPayload struct {
	Tenant    TenantID `json:"tenant"`
	Custodian string   `json:"custodian"`
	AuthGen   uint64   `json:"auth_gen"`
}

// RevokePayload removes a custodian and advances the authorization generation.
type RevokePayload struct {
	Tenant    TenantID `json:"tenant"`
	Custodian string   `json:"custodian"`
	AuthGen   uint64   `json:"auth_gen"`
	Reason    string   `json:"reason,omitempty"`
}

// MirrorPayload is the reconciliation log's copy of a custody change.  JournalSeq
// points back to the journal record so an auditor can tie the two chains.
type MirrorPayload struct {
	Grant     bool     `json:"grant"`
	Tenant    TenantID `json:"tenant"`
	Custodian string   `json:"custodian"`
	AuthGen   uint64   `json:"auth_gen"`
	JournalSeq uint64  `json:"journal_seq"`
	Reason    string   `json:"reason,omitempty"`
}

// Envelope is the metadata of one handover request.  Approvals are the two
// control-root signatures over Binding().
type Envelope struct {
	RequestID     string     `json:"request_id"`
	Case          CaseID     `json:"case"`
	Version       uint64     `json:"version"`
	PrevVersion   uint64     `json:"prev_version"`
	Digest        Digest     `json:"digest"`
	FromTenant    TenantID   `json:"from_tenant"`
	ToTenant      TenantID   `json:"to_tenant"`
	FromCustodian string     `json:"from_custodian"`
	ToCustodian   string     `json:"to_custodian"`
	AuthGen       uint64     `json:"auth_gen"`
	Approvals     []Approval `json:"approvals"`
}

// Binding reconstructs the signed message from the envelope.
func (e Envelope) Binding() ApprovalBinding {
	return ApprovalBinding{
		Case:        e.Case,
		Digest:      e.Digest,
		FromTenant:  e.FromTenant,
		ToTenant:    e.ToTenant,
		PrevVersion: e.PrevVersion,
		Version:     e.Version,
		AuthGen:     e.AuthGen,
	}
}

// PackMeta is the self-describing metadata stored next to the attachment bytes
// in each department's pack.  It omits approvals (proven by the logs); it binds
// the bytes to a case, version, tenants, previous version and auth generation,
// so recovery can rebuild a committed handover from the packs.
type PackMeta struct {
	RequestID     string   `json:"request_id"`
	Case          CaseID   `json:"case"`
	Version       uint64   `json:"version"`
	PrevVersion   uint64   `json:"prev_version"`
	Digest        Digest   `json:"digest"`
	FromTenant    TenantID `json:"from_tenant"`
	ToTenant      TenantID `json:"to_tenant"`
	FromCustodian string   `json:"from_custodian"`
	ToCustodian   string   `json:"to_custodian"`
	AuthGen       uint64   `json:"auth_gen"`
}

// Meta extracts the pack metadata from an envelope.
func (e Envelope) Meta() PackMeta {
	return PackMeta{
		RequestID:     e.RequestID,
		Case:          e.Case,
		Version:       e.Version,
		PrevVersion:   e.PrevVersion,
		Digest:        e.Digest,
		FromTenant:    e.FromTenant,
		ToTenant:      e.ToTenant,
		FromCustodian: e.FromCustodian,
		ToCustodian:   e.ToCustodian,
		AuthGen:       e.AuthGen,
	}
}

// PackHeader precedes the raw content in a pack record.
type PackHeader struct {
	Kind string   `json:"kind"`
	Meta PackMeta `json:"meta"`
}

// Pack kinds.
const (
	PackKindCandidate = "candidate"
	PackKindQuarantine = "quarantine"
)

// SideRef locates one department's stored copy inside its pack.  Offset and
// Length refer to the *content* bytes, not the envelope header.
type SideRef struct {
	Tenant TenantID `json:"tenant"`
	Offset int64    `json:"offset"`
	Length int64    `json:"length"`
	Digest Digest   `json:"digest"`
}

// AcceptPayload is an accepted handover in the journal.
type AcceptPayload struct {
	Envelope
	Refs []SideRef `json:"refs"`
}

// Custody status values.
const (
	CustodyActive  = "active"
	CustodyRevoked = "revoked"
	CustodyUnknown = "unknown"
)

// CustodySnapshot is the custody state of one named custodian at decision time.
type CustodySnapshot struct {
	Tenant    TenantID `json:"tenant"`
	Custodian string   `json:"custodian"`
	Status    string   `json:"status"`
	RevokeSeq uint64   `json:"revoke_seq,omitempty"`
}

// Outcome is the adjudication of one handover attempt.
type Outcome string

const (
	OutcomeAccepted  Outcome = "accepted"
	OutcomeDuplicate Outcome = "duplicate_same_content"
	OutcomeConflict  Outcome = "conflict_same_version_different_digest"
	OutcomeRejected  Outcome = "rejected"
)

// Rejection reason codes.
const (
	ReasonCustodianRevoked = "custodian_revoked"
	ReasonCustodianUnknown = "custodian_unknown"
	ReasonStaleAuthGen     = "stale_auth_gen"
	ReasonBadApproval      = "bad_approval"
	ReasonBadBinding       = "bad_binding"
	ReasonVersionGap       = "version_gap"
	ReasonStalePrevious    = "stale_previous_version"
	ReasonDigestMismatch   = "digest_mismatch"
	ReasonUnknownTenant    = "unknown_tenant"
	ReasonMissingPayload   = "missing_payload"
)

// AttemptPayload is one adjudicated handover attempt in the reconciliation log.
//
// Semantic ordering is journal order: JournalHeadAtDecision is the journal
// sequence the decision was made against.  Custody is the set of custody events
// with JournalSeq <= JournalHeadAtDecision, and the version baseline is the set
// of accepted commits with CommittedSeq <= JournalHeadAtDecision.  Storing the
// cut point (plus the derived values below) lets an independent verifier
// recompute custody, the version baseline and the whole policy outcome without
// the journal.
type AttemptPayload struct {
	Envelope
	ActualDigest   Digest `json:"actual_digest"`
	PayloadPresent bool   `json:"payload_present"`

	JournalHeadAtDecision uint64 `json:"journal_head_at_decision"`
	GlobalAuthGen         uint64 `json:"global_auth_gen"`
	PrevAcceptedVersion   uint64 `json:"prev_accepted_version"`

	FromCustody CustodySnapshot `json:"from_custody"`
	ToCustody   CustodySnapshot `json:"to_custody"`

	Outcome      Outcome           `json:"outcome"`
	Reason       string            `json:"reason,omitempty"`
	CommittedSeq uint64            `json:"committed_seq,omitempty"`
	Refs         []SideRef         `json:"refs,omitempty"`
	Quarantined  bool              `json:"quarantined,omitempty"`
	Recovered    bool              `json:"recovered,omitempty"`
	Details      map[string]string `json:"details,omitempty"`
}
