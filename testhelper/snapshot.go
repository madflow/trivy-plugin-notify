package testhelper

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// Utility function to read a file or fail the test
func MustReadFile(t *testing.T, filePath string) []byte {
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file %s: %v", filePath, err)
	}
	return data
}

// Utility function to handle snapshots generically
func HandleSnapshot(t *testing.T, snapshotPath string, actual []byte) {
	// Check if the snapshot file exists
	expected, err := os.ReadFile(snapshotPath)
	if os.IsNotExist(err) {
		// Snapshot does not exist, create it
		t.Logf("Snapshot does not exist, creating: %s", snapshotPath)
		err = os.MkdirAll(filepath.Dir(snapshotPath), os.ModePerm)
		if err != nil {
			t.Fatalf("failed to create snapshot directory: %v", err)
		}
		err = os.WriteFile(snapshotPath, actual, 0644)
		if err != nil {
			t.Fatalf("failed to write snapshot file: %v", err)
		}
		t.Skip("Snapshot created. Rerun the test to verify functionality.")
		return
	} else if err != nil {
		t.Fatalf("failed to read snapshot file: %v", err)
	}

	// Compare the actual data with the snapshot
	if !bytes.Equal(actual, expected) {
		diff := cmp.Diff(string(expected), string(actual))
		t.Errorf("snapshot mismatch:\nDiff (-expected +got):\n%s", diff)
	}
}
