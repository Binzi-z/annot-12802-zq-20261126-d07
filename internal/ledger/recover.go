package ledger

import (
	"encoding/json"
	"fmt"
	"sort"

	"handover/internal/model"
)

// RecoveryReport describes what Recover found and repaired.
type RecoveryReport struct {
	JournalSeq uint64
	ReconSeq   uint64
	// Reconstructed are journal-committed handovers whose reconciliation record
	// was lost to a crash, repaired as recovered attempts.
	Reconstructed []RecoveredAttempt
	// CorruptAccepts lists committed handovers whose bytes fail verification;
	// recovery refuses to proceed when any are present.
	CorruptAccepts   []string
	TruncatedJournal int64
	TruncatedRecon   int64
}

// RecoveredAttempt is one crash-repaired commit.
type RecoveredAttempt struct {
	Case      model.CaseID
	Version   uint64
	Seq       uint64
	RequestID string
	Digest    model.Digest
	Refs      []model.SideRef
}

// Recover re-opens the ledger directory, repairs a crash between the durable
// journal commit and the reconciliation response, verifies that every committed
// handover's bytes are actually present in both packs, and returns a
// deterministic report.  It is idempotent.
func Recover(cfg Config) (*Ledger, *RecoveryReport, error) {
	l, err := Open(cfg)
	if err != nil {
		return nil, nil, err
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	rep := &RecoveryReport{
		JournalSeq:       l.journal.LastSeq(),
		TruncatedJournal: l.journal.TruncatedBytes(),
		TruncatedRecon:   l.recon.TruncatedBytes(),
	}

	// Verify the actual bytes for every committed accept before repairing.
	accepts := l.journalAccepts()
	for _, acc := range accepts {
		for _, ref := range acc.payload.Refs {
			if err := l.verifyRef(ref); err != nil {
				rep.CorruptAccepts = append(rep.CorruptAccepts, fmt.Sprintf(
					"case %s v%d seq %d: %v", acc.payload.Case, acc.payload.Version, acc.seq, err))
			}
		}
	}
	if len(rep.CorruptAccepts) > 0 {
		sort.Strings(rep.CorruptAccepts)
		return l, rep, fmt.Errorf("recovery: %d committed handover(s) fail attachment check; first: %s",
			len(rep.CorruptAccepts), rep.CorruptAccepts[0])
	}

	// A reconciliation attempt is "recorded" if a record names the commit.
	recordedCommit := make(map[uint64]bool)
	for _, rec := range l.recon.Records() {
		if rec.Type != model.ReconAttempt {
			continue
		}
		var a model.AttemptPayload
		if err := json.Unmarshal(rec.Payload, &a); err != nil {
			return l, rep, fmt.Errorf("recon seq %d: %w", rec.Seq, err)
		}
		if a.Outcome == model.OutcomeAccepted && a.CommittedSeq != 0 {
			recordedCommit[a.CommittedSeq] = true
		}
	}

	for _, acc := range accepts {
		if recordedCommit[acc.seq] {
			continue
		}
		at, err := l.reconstructAttempt(acc)
		if err != nil {
			return l, rep, err
		}
		if _, err := l.recon.Append(model.ReconAttempt, at, l.cfg.Sync); err != nil {
			return l, rep, err
		}
		recordedCommit[acc.seq] = true
		l.seenRequests[at.RequestID] = true
		rep.Reconstructed = append(rep.Reconstructed, RecoveredAttempt{
			Case:      at.Case,
			Version:   at.Version,
			Seq:       acc.seq,
			RequestID: at.RequestID,
			Digest:    at.Digest,
			Refs:      at.Refs,
		})
	}
	sort.Slice(rep.Reconstructed, func(i, j int) bool {
		if rep.Reconstructed[i].Seq != rep.Reconstructed[j].Seq {
			return rep.Reconstructed[i].Seq < rep.Reconstructed[j].Seq
		}
		return rep.Reconstructed[i].Case < rep.Reconstructed[j].Case
	})
	rep.ReconSeq = l.recon.LastSeq()
	return l, rep, nil
}

type journalAccept struct {
	seq     uint64
	payload model.AcceptPayload
}

func (l *Ledger) journalAccepts() []journalAccept {
	var out []journalAccept
	for _, rec := range l.journal.Records() {
		if rec.Type != model.TypeAccept {
			continue
		}
		var a model.AcceptPayload
		if err := json.Unmarshal(rec.Payload, &a); err != nil {
			continue
		}
		out = append(out, journalAccept{seq: rec.Seq, payload: a})
	}
	return out
}

// verifyRef reads the bytes a journal accept points at and confirms the stored
// digest agrees with the reference.
func (l *Ledger) verifyRef(ref model.SideRef) error {
	p := l.packs[ref.Tenant]
	if p == nil {
		return fmt.Errorf("no pack for tenant %q", ref.Tenant)
	}
	content, err := p.ReadAt(ref.Offset, ref.Length)
	if err != nil {
		return err
	}
	if got := model.DigestOf(content); got != ref.Digest {
		return fmt.Errorf("pack bytes digest %s, ref says %s", got, ref.Digest)
	}
	return nil
}

// reconstructAttempt rebuilds the missing reconciliation record from the journal
// accept and the actual packs alone.
func (l *Ledger) reconstructAttempt(acc journalAccept) (model.AttemptPayload, error) {
	for _, ref := range acc.payload.Refs {
		content, err := l.packs[ref.Tenant].ReadAt(ref.Offset, ref.Length)
		if err != nil {
			return model.AttemptPayload{}, err
		}
		if model.DigestOf(content) != acc.payload.Digest {
			return model.AttemptPayload{}, fmt.Errorf(
				"reconstruct %s v%d: pack bytes do not match journal digest",
				acc.payload.Case, acc.payload.Version)
		}
	}
	// A reconstructed attempt is evaluated against the journal head it was
	// committed at, one sequence before the accept itself (the decision the
	// ledger would have made at that point).  The authorization generation is
	// recomputed at that head rather than taken from the current state, so a
	// repair is correct even if custody changed after the crash.
	head := acc.seq - 1
	at := model.AttemptPayload{
		Envelope:              acc.payload.Envelope,
		ActualDigest:          acc.payload.Digest,
		PayloadPresent:        true,
		JournalHeadAtDecision: head,
		GlobalAuthGen:         l.authGenAt(head),
		PrevAcceptedVersion:   acc.payload.PrevVersion,
		FromCustody:           l.snapshotAt(head, acc.payload.FromTenant, acc.payload.FromCustodian),
		ToCustody:             l.snapshotAt(head, acc.payload.ToTenant, acc.payload.ToCustodian),
		Outcome:               model.OutcomeAccepted,
		CommittedSeq:          acc.seq,
		Refs:                  acc.payload.Refs,
		Recovered:             true,
	}
	return at, nil
}

// VerifyRefsForTesting exposes ref verification to white-box tests.
func (l *Ledger) VerifyRefsForTesting(refs []model.SideRef) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, r := range refs {
		if err := l.verifyRef(r); err != nil {
			return err
		}
	}
	return nil
}

// ReconRecords returns a copy of the reconciliation log records.
func (l *Ledger) ReconRecords() []model.Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]model.Record(nil), l.recon.Records()...)
}

// JournalRecords returns a copy of the journal records.
func (l *Ledger) JournalRecords() []model.Record {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]model.Record(nil), l.journal.Records()...)
}
