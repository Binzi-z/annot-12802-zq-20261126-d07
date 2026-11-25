package model

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

// RootKey is one control root's public key together with the department it
// controls.  A root may only sign approvals for its own side; this is how the
// "two different control roots" rule is enforced structurally rather than by
// convention.
type RootKey struct {
	ID   string   `json:"id"`
	Pub  []byte   `json:"pub"`
	Dept TenantID `json:"dept"`
}

// Keyring maps control-root IDs to their public keys and departments.
type Keyring struct {
	roots map[string]RootKey
	order []string
}

// NewKeyring builds a keyring from roots in the given order.
func NewKeyring(roots ...RootKey) (*Keyring, error) {
	k := &Keyring{roots: make(map[string]RootKey)}
	for _, r := range roots {
		if r.ID == "" {
			return nil, errors.New("keyring: empty root id")
		}
		if r.Dept == "" {
			return nil, fmt.Errorf("keyring: root %q has no department", r.ID)
		}
		if len(r.Pub) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keyring: root %q has %d-byte key", r.ID, len(r.Pub))
		}
		if _, dup := k.roots[r.ID]; dup {
			return nil, fmt.Errorf("keyring: duplicate root %q", r.ID)
		}
		k.roots[r.ID] = RootKey{
			ID:   r.ID,
			Pub:  append([]byte(nil), r.Pub...),
			Dept: r.Dept,
		}
		k.order = append(k.order, r.ID)
	}
	if len(k.roots) < 2 {
		return nil, errors.New("keyring: need at least two control roots")
	}
	return k, nil
}

// Lookup returns the root for an ID.
func (k *Keyring) Lookup(id string) (RootKey, bool) {
	r, ok := k.roots[id]
	return r, ok
}

// IDs returns root IDs in insertion order.
func (k *Keyring) IDs() []string { return append([]string(nil), k.order...) }

// VerifyApproval checks one approval against the keyring and the binding.
func (k *Keyring) VerifyApproval(b ApprovalBinding, a Approval) error {
	r, ok := k.roots[a.Root]
	if !ok {
		return fmt.Errorf("approval: unknown control root %q", a.Root)
	}
	if a.Side != r.Dept {
		return fmt.Errorf("approval: root %q controls %q, cannot sign for %q",
			a.Root, r.Dept, a.Side)
	}
	if a.Side != b.FromTenant && a.Side != b.ToTenant {
		return fmt.Errorf("approval: root %q signed for foreign tenant %q", a.Root, a.Side)
	}
	if len(a.Sig) != ed25519.SignatureSize {
		return fmt.Errorf("approval: root %q signature has length %d", a.Root, len(a.Sig))
	}
	if !ed25519.Verify(ed25519.PublicKey(r.Pub), b.Bytes(), a.Sig) {
		return fmt.Errorf("approval: root %q signature does not verify", a.Root)
	}
	return nil
}

// VerifyApprovalSet enforces the full approval policy: exactly two approvals,
// one from each side, from two distinct roots, both over the same binding.
func (k *Keyring) VerifyApprovalSet(b ApprovalBinding, approvals []Approval) error {
	if len(approvals) != 2 {
		return fmt.Errorf("approval: want exactly 2 approvals, got %d", len(approvals))
	}
	seenRoot := make(map[string]bool, 2)
	seenSide := make(map[TenantID]bool, 2)
	for _, a := range approvals {
		if seenRoot[a.Root] {
			return fmt.Errorf("approval: control root %q approved twice", a.Root)
		}
		seenRoot[a.Root] = true
		if seenSide[a.Side] {
			return fmt.Errorf("approval: side %q approved twice", a.Side)
		}
		seenSide[a.Side] = true
		if err := k.VerifyApproval(b, a); err != nil {
			return err
		}
	}
	if !seenSide[b.FromTenant] || !seenSide[b.ToTenant] {
		return fmt.Errorf("approval: did not receive one approval per side (%q and %q)",
			b.FromTenant, b.ToTenant)
	}
	return nil
}

type keyringJSON struct {
	Roots []struct {
		ID   string `json:"id"`
		Dept string `json:"dept"`
		Pub  string `json:"pub"`
	} `json:"roots"`
}

// MarshalJSON keeps roots sorted for reproducible files.
func (k *Keyring) MarshalJSON() ([]byte, error) {
	var payload keyringJSON
	ids := append([]string(nil), k.order...)
	sort.Strings(ids)
	for _, id := range ids {
		r := k.roots[id]
		payload.Roots = append(payload.Roots, struct {
			ID   string `json:"id"`
			Dept string `json:"dept"`
			Pub  string `json:"pub"`
		}{ID: r.ID, Dept: string(r.Dept), Pub: base64.StdEncoding.EncodeToString(r.Pub)})
	}
	return json.Marshal(payload)
}

// ParseKeyringJSON is the inverse of Keyring.MarshalJSON.
func ParseKeyringJSON(data []byte) (*Keyring, error) {
	var payload keyringJSON
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, err
	}
	keys := make([]RootKey, 0, len(payload.Roots))
	for _, r := range payload.Roots {
		pub, err := base64.StdEncoding.DecodeString(r.Pub)
		if err != nil {
			return nil, err
		}
		keys = append(keys, RootKey{ID: r.ID, Pub: pub, Dept: TenantID(r.Dept)})
	}
	return NewKeyring(keys...)
}
