package report_test

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"handover/internal/fixture"
	"handover/internal/model"
)

// tamperLastAttachmentByte flips one content byte of the newest committed copy of
// the given case in DEPT-B's pack.  It walks the pack, finds a record whose
// metadata names the case, and corrupts its last content byte.
func tamperLastAttachmentByte(dir string, w *fixture.World, c model.CaseID) error {
	path := filepath.Join(dir, "packs", "attachments-"+string(w.TenantB)+".bin")
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	pos := int64(0)
	target := int64(-1)
	for pos < int64(len(raw)) {
		if int64(len(raw))-pos < 8 {
			break
		}
		hlen := int64(binary.LittleEndian.Uint64(raw[pos : pos+8]))
		if hlen < 0 || pos+8+hlen+8 > int64(len(raw)) {
			break
		}
		chead := pos + 8 + hlen
		clen := int64(binary.LittleEndian.Uint64(raw[chead : chead+8]))
		contentStart := chead + 8
		if clen < 0 || contentStart+clen > int64(len(raw)) {
			break
		}
		var hdr struct {
			Kind string         `json:"kind"`
			Meta model.PackMeta `json:"meta"`
		}
		if err := json.Unmarshal(raw[pos+8:chead], &hdr); err == nil && hdr.Meta.Case == c && clen > 0 {
			target = contentStart + clen - 1
		}
		pos = contentStart + clen
	}
	if target < 0 {
		return fmt.Errorf("no pack record for case %s in %s", c, path)
	}
	raw[target] ^= 0xFF
	return os.WriteFile(path, raw, 0o644)
}
