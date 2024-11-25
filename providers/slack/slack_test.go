package slack

import (
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/madflow/trivy-plugin-notify/environment"
	"github.com/madflow/trivy-plugin-notify/providers"
	"github.com/madflow/trivy-plugin-notify/testhelper"
)

func runNotificationTest(t *testing.T, fixtureFile, snapshotFile string) {
	// Load fixture data
	fixtureData := testhelper.MustReadFile(t, fixtureFile)

	var capturedRequest []byte
	// Set up the mock server
	ts := testhelper.SetupMockServer(t, &capturedRequest)
	defer ts.Close()

	// Set up the test environment and provider
	os.Setenv("SLACK_WEBHOOK", ts.URL)
	// Make sure we have the same result in every environment
	os.Setenv("CI", "")
	slackProvider := New()

	var report interface{}
	if err := json.Unmarshal(fixtureData, &report); err != nil {
		t.Fatalf("failed to unmarshal fixture data: %v", err)
	}
	notificationPayload := providers.NotificationPayload{
		EnvironmentCi: environment.DetectEnvironmentCi(),
		TrivyReport:   report,
	}

	err := slackProvider.Notify(notificationPayload)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	testhelper.HandleSnapshot(t, snapshotFile, capturedRequest)
}

func Test_notify(t *testing.T) {
	t.Run("notify slack webhook snapshot", func(t *testing.T) {
		fixtureName := "v0.57.0_vuln_secret_misconf.json"
		fixtureFile := fmt.Sprintf("./testdata/%s", fixtureName)
		snapshotFile := fmt.Sprintf("./testdata/snapshots/%s", fixtureName)

		runNotificationTest(t, fixtureFile, snapshotFile)
	})
}
