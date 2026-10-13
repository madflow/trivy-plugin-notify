package main

import (
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/madflow/trivy-plugin-notify/internal/util"
)

type testPayload struct {
	ArtifactName string
}

func isolateRunFlags(t *testing.T, args ...string) {
	t.Helper()
	oldFlags, oldArgs := flag.CommandLine, os.Args
	t.Cleanup(func() {
		flag.CommandLine, os.Args = oldFlags, oldArgs
	})
	flag.CommandLine = flag.NewFlagSet("notify-test", flag.ContinueOnError)
	os.Args = append([]string{"notify-test"}, args...)
}

func Test_isSupported(t *testing.T) {
	for _, name := range []string{"console", "email", "slack", "ntfy", "webhook", "unknown", ""} {
		t.Run(name, func(t *testing.T) {
			wantError := name == "unknown" || name == ""
			if err := isSupported(name); (err != nil) != wantError {
				t.Fatalf("isSupported(%q) = %v", name, err)
			}
		})
	}
}

func Test_runNtfy(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		report       util.TrivyReport
		status       int
		wantRequests string
		wantError    bool
		wantMessage  string
	}{
		{name: "success", report: util.TrivyReport{Results: []util.TrivyResult{{Vulnerabilities: []any{nil}}}}, wantRequests: "ntfy", wantMessage: "All notifications sent successfully."},
		{name: "failure stops dispatch", args: []string{"--providers=ntfy,webhook"}, report: util.TrivyReport{Results: []util.TrivyResult{{Secrets: []any{nil}}}}, status: 500, wantRequests: "ntfy", wantError: true, wantMessage: "Ntfy provider failed:"},
		{name: "empty skipped", wantMessage: "Skipping all notifications."},
		{name: "send always", args: []string{"--providers=ntfy", "--send-always"}, wantRequests: "ntfy", wantMessage: "All notifications sent successfully."},
		{name: "secret only", report: util.TrivyReport{Results: []util.TrivyResult{{Secrets: []any{nil}}}}, wantRequests: "ntfy", wantMessage: "All notifications sent successfully."},
		{name: "misconfiguration only", report: util.TrivyReport{Results: []util.TrivyResult{{Misconfigurations: []any{nil}}}}, wantRequests: "ntfy", wantMessage: "All notifications sent successfully."},
		{name: "license only", report: util.TrivyReport{Results: []util.TrivyResult{{Licenses: []any{nil}}}}, wantRequests: "ntfy", wantMessage: "All notifications sent successfully."},
		{name: "package only", report: util.TrivyReport{Results: []util.TrivyResult{{Packages: []any{nil}}}}, wantRequests: "ntfy", wantMessage: "All notifications sent successfully."},
		{name: "combined providers", args: []string{"--providers=ntfy,webhook"}, report: util.TrivyReport{Results: []util.TrivyResult{{Secrets: []any{nil}}}}, wantRequests: "ntfy,webhook", wantMessage: "All notifications sent successfully."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := tt.args
			if args == nil {
				args = []string{"--providers=ntfy"}
			}
			isolateRunFlags(t, args...)
			var requests []string
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests = append(requests, strings.TrimPrefix(r.URL.Path, "/"))
				_, _ = io.Copy(io.Discard, r.Body)
				if r.URL.Path == "/ntfy" && tt.status != 0 {
					w.WriteHeader(tt.status)
				}
			}))
			defer ts.Close()
			t.Setenv("NTFY_URL", ts.URL+"/ntfy")
			t.Setenv("NTFY_TOKEN", "")
			t.Setenv("WEBHOOK_URL", ts.URL+"/webhook")
			t.Setenv("WEBHOOK_METHOD", "POST")
			stats, err := util.CollectStatistics(tt.report)
			if err != nil {
				t.Fatal(err)
			}
			msg, err := run(tt.report, stats)
			if (err != nil) != tt.wantError {
				t.Fatalf("run error = %v, want error %v", err, tt.wantError)
			}
			if msg == nil || !strings.Contains(msg.Message, tt.wantMessage) {
				t.Fatalf("run message = %+v, want %q", msg, tt.wantMessage)
			}
			wantLevel := "info"
			if tt.wantError {
				wantLevel = "error"
			}
			if msg.Level != wantLevel {
				t.Errorf("level = %q, want %q", msg.Level, wantLevel)
			}
			if got := strings.Join(requests, ","); got != tt.wantRequests {
				t.Errorf("requests = %q, want %q", got, tt.wantRequests)
			}
		})
	}
}

func Test_run(t *testing.T) {
	t.Run("run", func(t *testing.T) {
		isolateRunFlags(t)
		stats := util.Statistics{}
		_, err := run(testPayload{}, stats)
		if err == nil {
			t.Errorf("expected an error")
		}
	})
}
