package scenarios_test

import (
	"os"
	"path/filepath"
)

func filepathJoin(elem ...string) string { return filepath.Join(elem...) }

// flipLastByte flips the final byte of a file, which lands inside the last
// committed content record.
func flipLastByte(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return os.ErrInvalid
	}
	data[len(data)-1] ^= 0xFF
	return os.WriteFile(path, data, 0o644)
}
