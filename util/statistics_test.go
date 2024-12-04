package util

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/madflow/trivy-plugin-notify/testhelper"
)

func Test_CollectStatistics(t *testing.T) {
	tests := []struct {
		name        string
		fixtureName string
	}{
		{
			name:        "vuln secret misconf report",
			fixtureName: "v0.57.0_vuln_secret_misconf.json",
		},
		{
			name:        "no results report",
			fixtureName: "no-results.json",
		},
		{
			name:        "empty results report",
			fixtureName: "empty-results.json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixtureFile := fmt.Sprintf("./testdata/%s", tt.fixtureName)
			snapshotFile := fmt.Sprintf("./testdata/snapshots/%s", tt.fixtureName)

			fixtureData := testhelper.MustReadFile(t, fixtureFile)
			var report interface{}
			if err := json.Unmarshal(fixtureData, &report); err != nil {
				t.Fatalf("failed to unmarshal fixture data: %v", err)
			}

			stats, err := CollectStatistics(report)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			statsBytes, _ := json.Marshal(stats)
			testhelper.HandleSnapshot(t, snapshotFile, statsBytes)
		})
	}
}
