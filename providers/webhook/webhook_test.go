package webhook

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/madflow/trivy-plugin-notify/report"
)

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

			data := types.Report{}
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

		data := report.Report{
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

			data := types.Report{}
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

		data := report.Report{
			ArtifactName: "test",
		}
		err := sendWebhookMessage(ts.URL, "GET", data)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
