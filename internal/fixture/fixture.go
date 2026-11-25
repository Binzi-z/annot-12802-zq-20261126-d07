// Package fixture builds synthetic-but-consistent handover inputs: control-root
// keys, departments, custodians, and signed requests.  It is shared by the
// tests and the command-line demo but contains no ledger policy.
package fixture

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"

	"handover/internal/ledger"
	"handover/internal/model"
)

// Root is a control root's signing material plus its public description.
type Root struct {
	ID   string
	Dept model.TenantID
	Pub  ed25519.PublicKey
	Priv ed25519.PrivateKey
}

// World is a complete, self-consistent handover fixture.
type World struct {
	TenantA model.TenantID
	TenantB model.TenantID
	RootA   Root
	RootB   Root
	Keyring *model.Keyring

	// Signers indexed by department.
	signers map[model.TenantID]ledger.Signer
}

// NewWorld builds the canonical two-department world.  Keys are derived from a
// fixed seed so tests are reproducible.
func NewWorld() (*World, error) {
	rootA, err := deriveRoot("ROOT-A", "DEPT-A", "fixture-root-a-seed")
	if err != nil {
		return nil, err
	}
	rootB, err := deriveRoot("ROOT-B", "DEPT-B", "fixture-root-b-seed")
	if err != nil {
		return nil, err
	}
	kr, err := model.NewKeyring(
		model.RootKey{ID: rootA.ID, Pub: rootA.Pub, Dept: rootA.Dept},
		model.RootKey{ID: rootB.ID, Pub: rootB.Pub, Dept: rootB.Dept},
	)
	if err != nil {
		return nil, err
	}
	w := &World{
		TenantA: rootA.Dept,
		TenantB: rootB.Dept,
		RootA:   rootA,
		RootB:   rootB,
		Keyring: kr,
		signers: make(map[model.TenantID]ledger.Signer),
	}
	w.signers[rootA.Dept] = ledger.Signer{Root: rootA.ID, Dept: rootA.Dept, Priv: rootA.Priv}
	w.signers[rootB.Dept] = ledger.Signer{Root: rootB.ID, Dept: rootB.Dept, Priv: rootB.Priv}
	return w, nil
}

func deriveRoot(id, dept, seed string) (Root, error) {
	sum := sha256.Sum256([]byte(seed))
	priv := ed25519.NewKeyFromSeed(sum[:])
	pub := priv.Public().(ed25519.PublicKey)
	return Root{ID: id, Dept: model.TenantID(dept), Pub: pub, Priv: priv}, nil
}

// Signers returns the two signers keyed by department.
func (w *World) Signers() map[model.TenantID]ledger.Signer {
	out := make(map[model.TenantID]ledger.Signer, len(w.signers))
	for k, v := range w.signers {
		out[k] = v
	}
	return out
}

// GenesisCustodians returns the starting custodian per tenant.
func (w *World) GenesisCustodians() map[model.TenantID]string {
	return map[model.TenantID]string{
		w.TenantA: "CUST-A1",
		w.TenantB: "CUST-B1",
	}
}

// Binding builds the canonical approval binding for a request.
func (w *World) Binding(caseID model.CaseID, payload []byte, from, to model.TenantID,
	prevVersion, version, authGen uint64) model.ApprovalBinding {
	return model.ApprovalBinding{
		Case:        caseID,
		Digest:      model.DigestOf(payload),
		FromTenant:  from,
		ToTenant:    to,
		PrevVersion: prevVersion,
		Version:     version,
		AuthGen:     authGen,
	}
}

// SignedRequest builds a request signed by both roots over the same binding.
func (w *World) SignedRequest(caseID model.CaseID, payload []byte, from, to model.TenantID,
	fromCust, toCust string, prevVersion, version, authGen uint64) (ledger.Request, error) {
	b := w.Binding(caseID, payload, from, to, prevVersion, version, authGen)
	appr := []model.Approval{
		w.signers[from].Sign(b),
		w.signers[to].Sign(b),
	}
	if err := w.Keyring.VerifyApprovalSet(b, appr); err != nil {
		return ledger.Request{}, fmt.Errorf("fixture: self-signed request failed verification: %w", err)
	}
	return ledger.Request{
		Envelope: model.Envelope{
			RequestID:     fmt.Sprintf("%s/%s/v%d", caseID, from, version),
			Case:          caseID,
			Version:       version,
			PrevVersion:   prevVersion,
			Digest:        b.Digest,
			FromTenant:    from,
			ToTenant:      to,
			FromCustodian: fromCust,
			ToCustodian:   toCust,
			AuthGen:       authGen,
			Approvals:     appr,
		},
		Payload: payload,
		Present: true,
	}, nil
}

// Payload builds deterministic attachment bytes for a case and version.
func Payload(caseID model.CaseID, version uint64, salt uint64) []byte {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], version)
	binary.BigEndian.PutUint64(b[8:], salt)
	sum := sha256.Sum256([]byte(string(caseID)))
	return []byte(fmt.Sprintf("closure-attachment|case=%s|v=%d|salt=%d|h=%x",
		caseID, version, salt, sum[:8]))
}

// SortedTenants returns the two tenants in stable order.
func SortedTenants(a, b model.TenantID) []model.TenantID {
	out := []model.TenantID{a, b}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
