// Package wire owns the on-disk byte formats: two hash-chained JSONL logs and
// one append-only attachment pack per department.
//
// The ledger is the only writer.  The independent verifier deliberately does
// *not* import this package; it re-implements the readers so that a bug here
// cannot silently validate itself.
package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"handover/internal/model"
)

// Log is an append-only, hash-chained JSONL log.  A torn final record is
// truncated on open: a crash can leave a partial write, but a fully written
// record is always newline-terminated.
type Log struct {
	mu      sync.Mutex
	path    string
	domain  string
	file    *os.File
	records []model.Record
	trunc   int64
}

// OpenLog opens or creates a log at path, verifies its chain and truncates a
// torn tail.
func OpenLog(path, domain string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	l := &Log{path: path, domain: domain}
	if err := l.load(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	l.file = f
	return l, nil
}

func (l *Log) load() error {
	raw, err := os.ReadFile(l.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var prev model.Digest
	var seq uint64
	pos := 0
	validEnd := 0
	for pos < len(raw) {
		nl := bytes.IndexByte(raw[pos:], '\n')
		if nl < 0 {
			// Torn tail: trailing bytes with no newline.  Because each record is
			// written as one buffer ending in '\n' and JSON never contains a raw
			// newline, a complete record is always newline-terminated.
			break
		}
		line := raw[pos : pos+nl]
		pos += nl + 1

		var rec model.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			// A newline-terminated line must be a complete record; failing to
			// parse it means the log is corrupt, not that it was torn.
			return fmt.Errorf("%s: corrupt record at byte %d: %w", l.path, validEnd, err)
		}
		if rec.Seq != seq+1 {
			return fmt.Errorf("%s: record at byte %d has seq %d, want %d",
				l.path, validEnd, rec.Seq, seq+1)
		}
		if err := model.VerifyChain(l.domain, rec, prev); err != nil {
			return fmt.Errorf("%s: %w", l.path, err)
		}
		l.records = append(l.records, rec)
		prev = rec.Hash
		seq = rec.Seq
		validEnd = pos
	}
	if validEnd != len(raw) {
		if err := truncateTo(l.path, int64(validEnd)); err != nil {
			return err
		}
		l.trunc = int64(len(raw) - validEnd)
	}
	return nil
}

func truncateTo(path string, size int64) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.Size() <= size {
		return nil
	}
	return os.Truncate(path, size)
}

// TruncatedBytes reports how many torn bytes were removed on open.
func (l *Log) TruncatedBytes() int64 { return l.trunc }

// Records returns the verified records.
func (l *Log) Records() []model.Record { return l.records }

// Head returns the chain head and the next sequence number.
func (l *Log) Head() (model.Digest, uint64) {
	if len(l.records) == 0 {
		return model.Digest{}, 1
	}
	last := l.records[len(l.records)-1]
	return last.Hash, last.Seq + 1
}

// LastSeq returns the last record sequence, or zero for an empty log.
func (l *Log) LastSeq() uint64 {
	if len(l.records) == 0 {
		return 0
	}
	return l.records[len(l.records)-1].Seq
}

// Append durably writes one record.  The whole line is written with a single
// Write call so a crash yields either nothing or a newline-terminated record.
func (l *Log) Append(typ string, payload interface{}, sync bool) (model.Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev, seq := l.Head()
	rec, err := model.MakeRecord(l.domain, prev, seq, typ, payload)
	if err != nil {
		return model.Record{}, err
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return model.Record{}, err
	}
	buf := make([]byte, 0, len(line)+1)
	buf = append(buf, line...)
	buf = append(buf, '\n')
	if _, err := l.file.Write(buf); err != nil {
		return model.Record{}, err
	}
	if sync {
		if err := l.file.Sync(); err != nil {
			return model.Record{}, err
		}
	}
	l.records = append(l.records, rec)
	return rec, nil
}

// Sync flushes the log.
func (l *Log) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.file.Sync()
}

// Close flushes and closes the log.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Sync()
	if cerr := l.file.Close(); err == nil {
		err = cerr
	}
	l.file = nil
	return err
}

// Pack is an append-only attachment pack for one department.  Each record is
//
//	u64le(headerLen) | header JSON | u64le(contentLen) | content
//
// The self-describing metadata travels with the bytes, so recovery can rebuild
// a committed handover from the actual attachment packs.
type Pack struct {
	mu      sync.Mutex
	tenant  model.TenantID
	path    string
	file    *os.File
	entries []Entry
	trunc   int64
}

// Entry is one pack record's index entry.
type Entry struct {
	Kind   string
	Meta   model.PackMeta
	Offset int64
	Length int64
	Digest model.Digest
}

// OpenPack opens or creates a pack for tenant, parsing and truncating a torn
// tail.
func OpenPack(path string, tenant model.TenantID) (*Pack, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	p := &Pack{tenant: tenant, path: path}
	if err := p.load(); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	p.file = f
	return p, nil
}

func (p *Pack) load() error {
	data, err := os.ReadFile(p.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	off := int64(0)
	validEnd := int64(0)
	for off < int64(len(data)) {
		rest := data[off:]
		if len(rest) < 8 {
			break
		}
		hlen := int64(binary.LittleEndian.Uint64(rest[:8]))
		if hlen < 0 || hlen > int64(len(rest))-8 {
			break
		}
		header := rest[8 : 8+hlen]
		afterHeader := 8 + hlen
		if int64(len(rest)) < afterHeader+8 {
			break
		}
		clen := int64(binary.LittleEndian.Uint64(rest[afterHeader : afterHeader+8]))
		contentStart := afterHeader + 8
		if clen < 0 || clen > int64(len(rest))-contentStart {
			break
		}
		var hdr model.PackHeader
		if err := json.Unmarshal(header, &hdr); err != nil {
			break
		}
		content := rest[contentStart : contentStart+clen]
		p.entries = append(p.entries, Entry{
			Kind:   hdr.Kind,
			Meta:   hdr.Meta,
			Offset: off + contentStart,
			Length: clen,
			Digest: model.DigestOf(content),
		})
		off += contentStart + clen
		validEnd = off
	}
	if validEnd != int64(len(data)) {
		if err := os.Truncate(p.path, validEnd); err != nil {
			return err
		}
		p.trunc = int64(len(data)) - validEnd
	}
	return nil
}

// TruncatedBytes reports torn bytes removed on open.
func (p *Pack) TruncatedBytes() int64 { return p.trunc }

// Append writes one record and returns its entry and reference.  The caller
// hashes/validates the content before calling; Append recomputes the digest
// from the bytes it actually persisted.
func (p *Pack) Append(meta model.PackMeta, content []byte, sync bool) (Entry, model.SideRef, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	hdr, err := json.Marshal(model.PackHeader{Kind: model.PackKindCandidate, Meta: meta})
	if err != nil {
		return Entry{}, model.SideRef{}, err
	}
	fi, err := p.file.Stat()
	if err != nil {
		return Entry{}, model.SideRef{}, err
	}
	start := fi.Size()
	contentStart := start + 8 + int64(len(hdr)) + 8

	var num [8]byte
	binary.LittleEndian.PutUint64(num[:], uint64(len(hdr)))
	if _, err := p.file.Write(num[:]); err != nil {
		return Entry{}, model.SideRef{}, err
	}
	if _, err := p.file.Write(hdr); err != nil {
		return Entry{}, model.SideRef{}, err
	}
	binary.LittleEndian.PutUint64(num[:], uint64(len(content)))
	if _, err := p.file.Write(num[:]); err != nil {
		return Entry{}, model.SideRef{}, err
	}
	if _, err := p.file.Write(content); err != nil {
		return Entry{}, model.SideRef{}, err
	}
	if sync {
		if err := p.file.Sync(); err != nil {
			return Entry{}, model.SideRef{}, err
		}
	}
	digest := model.DigestOf(content)
	e := Entry{Kind: model.PackKindCandidate, Meta: meta, Offset: contentStart, Length: int64(len(content)), Digest: digest}
	p.entries = append(p.entries, e)
	return e, model.SideRef{Tenant: p.tenant, Offset: contentStart, Length: int64(len(content)), Digest: digest}, nil
}

// ReadAt returns content bytes.
func (p *Pack) ReadAt(off, length int64) ([]byte, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return readFullAt(p.file, off, length)
}

// Tenant returns the pack's department.
func (p *Pack) Tenant() model.TenantID { return p.tenant }

// Entries returns a copy of the pack index.
func (p *Pack) Entries() []Entry {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]Entry(nil), p.entries...)
}

// Sync flushes the pack.
func (p *Pack) Sync() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.file.Sync()
}

// Close flushes and closes the pack.
func (p *Pack) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.file == nil {
		return nil
	}
	err := p.file.Sync()
	if cerr := p.file.Close(); err == nil {
		err = cerr
	}
	p.file = nil
	return err
}

func readFullAt(f *os.File, off, length int64) ([]byte, error) {
	if length < 0 || off < 0 {
		return nil, fmt.Errorf("read: negative range [%d,%d)", off, off+length)
	}
	buf := make([]byte, length)
	read := 0
	for read < len(buf) {
		n, err := f.ReadAt(buf[read:], off+int64(read))
		read += n
		if err != nil {
			if errors.Is(err, io.EOF) && read == len(buf) {
				break
			}
			return nil, fmt.Errorf("read [%d,%d) at %d bytes: %w", off, off+length, read, err)
		}
	}
	return buf, nil
}
