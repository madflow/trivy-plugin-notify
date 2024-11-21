package webhook

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/madflow/trivy-plugin-notify/environment"
	"github.com/madflow/trivy-plugin-notify/providers"
	"github.com/madflow/trivy-plugin-notify/testhelper"
)

type testPayload struct {
	ArtifactName string
}

func Test_sendWebhookMessage(t *testing.T) {
	t.Run("webhook success post", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("unexpected method: %v", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected content type: %v", r.Header.Get("Content-Type"))
			}
			// read the body
			body := r.Body
			defer body.Close()

			data := testPayload{}
			err := json.NewDecoder(body).Decode(&data)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if data.ArtifactName != "test" {
				t.Errorf("unexpected artifact name: %v", data.ArtifactName)
			}

			fmt.Fprintf(w, "webhook success")
		}))
		defer ts.Close()

		data := testPayload{
			ArtifactName: "test",
		}
		err := sendWebhookMessage(ts.URL, "POST", data)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("webhook success get", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" {
				t.Errorf("unexpected method: %v", r.Method)
			}
			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected content type: %v", r.Header.Get("Content-Type"))
			}

			query := r.URL.Query()
			if query.Get("vulnerabilities") == "" {
				t.Errorf("missing vulnerabilities query parameter")
			}
			paramData := query.Get("vulnerabilities")

			data := testPayload{}
			err := json.Unmarshal([]byte(paramData), &data)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if data.ArtifactName != "test" {
				t.Errorf("unexpected artifact name: %v", data.ArtifactName)
			}

			fmt.Fprintf(w, "webhook success")
		}))
		defer ts.Close()

		data := map[string]string{}
		data["ArtifactName"] = "test"

		err := sendWebhookMessage(ts.URL, "GET", data)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}

func runNotificationTest(t *testing.T, fixtureFile, snapshotFile string) {
	fixtureData := testhelper.MustReadFile(t, fixtureFile)

	var capturedRequest []byte
	ts := testhelper.SetupMockServer(t, &capturedRequest)
	defer ts.Close()

	os.Setenv("WEBHOOK_URL", ts.URL)
	webhookProvider := New()

	var report interface{}
	if err := json.Unmarshal(fixtureData, &report); err != nil {
		t.Fatalf("failed to unmarshal fixture data: %v", err)
	}
	notificationPayload := providers.NotificationPayload{
		EnvironmentCi: environment.DetectEnvironmentCi(),
		TrivyReport:   report,
	}

	err := webhookProvider.Notify(notificationPayload)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	testhelper.HandleSnapshot(t, snapshotFile, capturedRequest)
}

func Test_notify(t *testing.T) {
	t.Run("notify webhook success snapshot", func(t *testing.T) {
		fixtureName := "v0.57.0_vuln_secret_misconf.json"
		fixtureFile := fmt.Sprintf("./testdata/%s", fixtureName)
		snapshotFile := fmt.Sprintf("./testdata/snapshots/%s", fixtureName)

		runNotificationTest(t, fixtureFile, snapshotFile)
	})
}
