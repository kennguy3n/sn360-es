package translation

import (
	"io/fs"
	"os"
)

// openOS / readDirOS / readFileOS keep the std-lib boundary in one file
// so the test fixtures can stub them when running against an alternate
// filesystem (e.g. testing/fstest.MapFS).
func openOS(name string) (fs.File, error)          { return os.Open(name) }
func readDirOS(name string) ([]fs.DirEntry, error) { return os.ReadDir(name) }
func readFileOS(name string) ([]byte, error)       { return os.ReadFile(name) }
