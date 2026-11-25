// Package model holds the shared wire types, canonical encodings and
// cryptographic bindings for the offline closure-attachment handover ledger.
//
// The package contains no policy decisions.  The ledger and the independent
// verifier both consume these types but implement their own validation paths,
// so a bug in one does not automatically propagate to the other.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// TenantID identifies one department in a handover.  In the synthetic data set
// the two tenants are "DEPT-A" and "DEPT-B".
type TenantID string

// CaseID identifies one closure case file.
type CaseID string

// Digest is a SHA-256 digest.  It marshals as lowercase hex so journals and
// reports stay human readable.
type Digest [32]byte

// DigestOf computes the SHA-256 digest of b.
func DigestOf(b []byte) Digest { return sha256.Sum256(b) }

func (d Digest) String() string { return hex.EncodeToString(d[:]) }

func (d Digest) IsZero() bool { return d == Digest{} }

func (d Digest) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

func (d *Digest) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	p, err := ParseDigest(s)
	if err != nil {
		return err
	}
	*d = p
	return nil
}

// ParseDigest parses exactly 64 hex characters.
func ParseDigest(s string) (Digest, error) {
	var d Digest
	if len(s) != 64 {
		return d, fmt.Errorf("digest: want 64 hex chars, got %d", len(s))
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return d, fmt.Errorf("digest: %w", err)
	}
	copy(d[:], raw)
	return d, nil
}

// MustDigest is a helper for tests and fixtures; it panics on bad input.
func MustDigest(s string) Digest {
	d, err := ParseDigest(s)
	if err != nil {
		panic(err)
	}
	return d
}

// Approval is one control root's signature over an ApprovalBinding for exactly
// one side of the handover.  The same control root may not sign both sides:
// policy requires two *different* roots.
type Approval struct {
	// Root is the control-root identifier, e.g. "ROOT-A".
	Root string `json:"root"`
	// Side is the tenant whose records this root controls.
	Side TenantID `json:"side"`
	// Sig is the detached Ed25519 signature over ApprovalBinding.Bytes().
	Sig []byte `json:"sig"`
}

// ApprovalBinding is the canonical, domain-separated message that both control
// roots sign.  It binds the attachment digest, both tenants, the previous
// revision and the authorization generation.  Nothing here is optional: an
// approval that omits or disagrees on any field is rejected.
type ApprovalBinding struct {
	Case        CaseID   `json:"case"`
	Digest      Digest   `json:"digest"`
	FromTenant  TenantID `json:"from_tenant"`
	ToTenant    TenantID `json:"to_tenant"`
	PrevVersion uint64   `json:"prev_version"`
	Version     uint64   `json:"version"`
	AuthGen     uint64   `json:"auth_gen"`
}

// approvalDomain is prepended to every binding so signatures cannot be lifted
// into another protocol.
const approvalDomain = "handover-approval-v1\x00"

// Bytes returns the canonical encoding that control roots sign.
func (b ApprovalBinding) Bytes() []byte {
	// Fixed field order, length-prefixed strings, big-endian integers.  This is
	// intentionally hand-rolled rather than JSON so that no encoder quirk can
	// make the ledger and verifier disagree.
	var out []byte
	out = append(out, approvalDomain...)
	out = appendString(out, string(b.Case))
	out = append(out, b.Digest[:]...)
	out = appendString(out, string(b.FromTenant))
	out = appendString(out, string(b.ToTenant))
	out = appendUint64(out, b.PrevVersion)
	out = appendUint64(out, b.Version)
	out = appendUint64(out, b.AuthGen)
	return out
}

// ValidateShape checks structural invariants that do not need cryptography or
// ledger state.  The version/predecessor relationship is *policy* (it depends on
// what is already committed), so it is checked by the ledger, not here.
func (b ApprovalBinding) ValidateShape() error {
	if b.Case == "" {
		return errors.New("approval: empty case")
	}
	if b.Digest.IsZero() {
		return errors.New("approval: empty digest")
	}
	if b.FromTenant == "" || b.ToTenant == "" {
		return errors.New("approval: empty tenant")
	}
	if b.FromTenant == b.ToTenant {
		return errors.New("approval: both sides must differ")
	}
	if b.Version == 0 {
		return errors.New("approval: version must be >= 1")
	}
	if b.AuthGen == 0 {
		return errors.New("approval: auth generation must be >= 1")
	}
	return nil
}

func appendString(dst []byte, s string) []byte {
	dst = appendUint64(dst, uint64(len(s)))
	return append(dst, s...)
}

func appendUint64(dst []byte, v uint64) []byte {
	var b [8]byte
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
	return append(dst, b[:]...)
}
