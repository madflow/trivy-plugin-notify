package slack

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/madflow/trivy-plugin-notify/environment"
	"github.com/madflow/trivy-plugin-notify/providers"
)

func Test_sendSlackMessage(t *testing.T) {
	t.Run("slack webhook success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("unexpected method: %v", r.Method)
			}

			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected content type: %v", r.Header.Get("Content-Type"))
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{ "ok": true }`)
		}))
		defer ts.Close()

		err := sendSlackMessage(ts.URL, new(bytes.Buffer))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func Test_notify(t *testing.T) {
	fixtureName := "v0.57.0_vuln_secret_misconf.json"
	fixtureFile := fmt.Sprintf("./testdata/%s", fixtureName)
	snapshotFile := fmt.Sprintf("./testdata/snapshots/%s", fixtureName)

	// Load fixture data
	f, err := os.ReadFile(fixtureFile)
	if err != nil {
		t.Fatalf("failed to read fixture file: %v", err)
	}

	t.Run("notify slack webhook success snapshot", func(t *testing.T) {
		var capturedRequest []byte

		// Create a mock server to capture the request
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Capture the incoming request body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("failed to read request body: %v", err)
			}
			capturedRequest = body

			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{ "ok": true }`)
		}))
		defer ts.Close()

		// Call the Notify method
		os.Setenv("SLACK_WEBHOOK", ts.URL)
		slackProvider := New()
		var report interface{}
		if err := json.Unmarshal(f, &report); err != nil {
			t.Fatalf("failed to read fixture file: %v", err)
		}
		notificationPayload := providers.NotificationPayload{
			EnvironmentCi: environment.DetectEnvironmentCi(),
			TrivyReport:   report,
		}
		err := slackProvider.Notify(notificationPayload)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		// Check if the snapshot file exists
		expectedSnapshot, err := os.ReadFile(snapshotFile)
		if os.IsNotExist(err) {
			// Snapshot does not exist, create it
			t.Logf("Snapshot does not exist, creating it: %s", snapshotFile)
			err = os.MkdirAll(filepath.Dir(snapshotFile), os.ModePerm)
			if err != nil {
				t.Fatalf("failed to create snapshot directory: %v", err)
			}
			err = os.WriteFile(snapshotFile, capturedRequest, 0644)
			if err != nil {
				t.Fatalf("failed to write new snapshot file: %v", err)
			}
			t.Skip("Snapshot created. Rerun the test to verify functionality.")
		} else if err != nil {
			t.Fatalf("failed to read snapshot file: %v", err)
		}

		// Compare the captured request with the existing snapshot
		if !bytes.Equal(capturedRequest, expectedSnapshot) {
			t.Errorf(
				"request payload does not match snapshot:\nGot:\n%s\nExpected:\n%s",
				capturedRequest,
				expectedSnapshot,
			)
		}
	})
}
