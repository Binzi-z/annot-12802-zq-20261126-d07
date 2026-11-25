package scenarios_test

import (
	"strings"
	"testing"

	"handover/internal/audit"
	"handover/internal/fixture"
	"handover/internal/ledger"
	"handover/internal/model"
	"handover/internal/scenarios"
)

// TestRecoveryRecomputesFromAttachmentsAndLog proves the recovery report and the
// independent audit are reconstructed from the actual attachments plus the
// reconciliation log — not from any in-memory state — by reopening from disk and
// confirming the reconstructed attempt's digest matches the bytes on disk.
func TestRecoveryRecomputesFromAttachmentsAndLog(t *testing.T) {
	env, cleanup, err := scenarios.TempEnv(true)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	rec, err := scenarios.BarrierCommittedButUnacknowledged(env)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Reconstructed) != 1 {
		t.Fatalf("reconstructed %d, want 1", len(rec.Reconstructed))
	}
	got := rec.Reconstructed[0]

	// The committed digest must equal the digest of the actual bytes in BOTH
	// departments' packs.  Recompute it by re-opening the ledger and asking it to
	// verify the referenced copies.
	if err := env.L.VerifyRefsForTesting(got.Refs); err != nil {
		t.Fatalf("recovered refs do not verify against actual bytes: %v", err)
	}
	if len(got.Refs) != 2 {
		t.Fatalf("recovered %d copies, want 2", len(got.Refs))
	}
	wantDigest := model.DigestOf(fixture.Payload("CASE-CRASH", 1, 1))
	if got.Digest != wantDigest {
		t.Fatalf("recovered digest %s, want %s", got.Digest, wantDigest)
	}

	rep, err := audit.Verify(env.Dir, env.W.Keyring)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK() {
		t.Fatalf("audit: %s", scenarios.Report(rep))
	}
	if rep.Recovered != 1 {
		t.Fatalf("audit recovered = %d, want 1", rep.Recovered)
	}
}

// TestRecoveryDetectsMissingAttachment proves recovery refuses to paper over a
// committed handover whose bytes vanish, rather than reconstructing a false
// success.
func TestRecoveryDetectsMissingAttachment(t *testing.T) {
	env, cleanup, err := scenarios.TempEnv(true)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if _, _, err := env.V1("CASE-OK", 1); err != nil {
		t.Fatal(err)
	}
	if err := env.Close(); err != nil {
		t.Fatal(err)
	}
	// Corrupt one committed copy by flipping a content byte.
	path := filepathJoin(env.Dir, "packs", "attachments-"+string(env.W.TenantB)+".bin")
	if err := flipLastByte(path); err != nil {
		t.Fatal(err)
	}

	_, rep, err := ledger.Recover(ledger.Config{Dir: env.Dir, Keyring: env.W.Keyring, Sync: true})
	if err == nil {
		t.Fatal("recovery succeeded despite a corrupted committed attachment")
	}
	if len(rep.CorruptAccepts) == 0 {
		t.Fatalf("expected corrupt accepts; report: %+v", rep)
	}
	if !strings.Contains(err.Error(), "attachment check") {
		t.Fatalf("unexpected recovery error: %v", err)
	}
}
