package ntfy

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/madflow/trivy-plugin-notify/internal/environment"
	"github.com/madflow/trivy-plugin-notify/internal/provider"
	"github.com/madflow/trivy-plugin-notify/internal/util"
)

func TestProviderNtfy_Name(t *testing.T) {
	if got := New().Name(); got != "ntfy" {
		t.Fatalf("Name() = %q, want ntfy", got)
	}
}

func TestProviderNtfy_Notify(t *testing.T) {
	var decoded any
	if err := json.Unmarshal([]byte(`{"ArtifactName":"./testdata/security-fail/","Results":[{"Vulnerabilities":[{},{}],"Secrets":[{}],"Misconfigurations":[{}],"Licenses":[{}],"Packages":[{},{},{}]}]}`), &decoded); err != nil {
		t.Fatal(err)
	}
	typed := util.TrivyReport{ArtifactName: "./testdata/security-fail/", Results: []util.TrivyResult{{
		Vulnerabilities: []any{nil, nil}, Secrets: []any{nil},
		Misconfigurations: []any{nil}, Licenses: []any{nil}, Packages: []any{nil, nil, nil},
	}}}
	const counts = "\nVulnerabilities: 2\nSecrets: 1\nMisconfigurations: 1\nLicenses: 1\nPackages: 3\nTotal: 8\n"
	const summary = "Source: ./testdata/security-fail/\n" + counts
	const zeroSummary = "Source: unknown (report contains no artifact name or targets)\n\nVulnerabilities: 0\nSecrets: 0\nMisconfigurations: 0\nLicenses: 0\nPackages: 0\nTotal: 0\n"
	tests := []struct {
		name   string
		report any
		token  string
		status int
		body   string
		ci     environment.EnvironmentCi
	}{
		{name: "decoded with token", report: decoded, token: "secret-token", status: 200, body: summary},
		{name: "typed without token", report: typed, status: 201, body: summary},
		{name: "zero counts", report: util.TrivyReport{}, status: 204, body: zeroSummary},
		{name: "local context omitted", report: typed, status: 200, body: summary, ci: environment.LocalEnvironment()},
		{
			name: "CI context", report: decoded, status: 200,
			ci:   environment.EnvironmentCi{Provider: "github", Project: "org/repo", Ref: "main", Url: "https://github.com/org/repo/actions/runs/123"},
			body: "Source: ./testdata/security-fail/\nCI provider: github\nProject: org/repo\nRef: main\nURL: https://github.com/org/repo/actions/runs/123\n" + counts,
		},
		{
			name: "partial CI context", report: typed, status: 200,
			ci:   environment.EnvironmentCi{Provider: "gitlab", Project: "org/repo"},
			body: "Source: ./testdata/security-fail/\nCI provider: gitlab\nProject: org/repo\n" + counts,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requests := 0
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if r.Method != http.MethodPost || r.URL.Path != "/trivy" {
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
				}
				if got := r.Header.Get("Content-Type"); got != "text/plain; charset=utf-8" {
					t.Errorf("Content-Type = %q", got)
				}
				if got := r.Header.Get("Title"); got != "Trivy scan results" {
					t.Errorf("Title = %q", got)
				}
				wantAuth := ""
				if tt.token != "" {
					wantAuth = "Bearer " + tt.token
				}
				if got := r.Header.Get("Authorization"); got != wantAuth {
					t.Errorf("Authorization = %q, want %q", got, wantAuth)
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				if string(body) != tt.body {
					t.Errorf("body = %q, want %q", body, tt.body)
				}
				w.WriteHeader(tt.status)
			}))
			defer ts.Close()
			t.Setenv("NTFY_URL", ts.URL+"/trivy")
			t.Setenv("NTFY_TOKEN", tt.token)
			if err := New().Notify(provider.NotificationPayload{TrivyReport: tt.report, EnvironmentCi: tt.ci}); err != nil {
				t.Fatal(err)
			}
			if requests != 1 {
				t.Fatalf("requests = %d, want 1", requests)
			}
		})
	}
}

func Test_reportSource(t *testing.T) {
	tests := []struct {
		name   string
		report any
		want   string
	}{
		{name: "image", report: map[string]any{"ArtifactName": "debian:12"}, want: "debian:12"},
		{name: "artifact preferred", report: util.TrivyReport{ArtifactName: "repo", Results: []util.TrivyResult{{Target: "Dockerfile"}}}, want: "repo"},
		{name: "typed targets", report: util.TrivyReport{Results: []util.TrivyResult{{Target: "Dockerfile"}, {Target: "yarn.lock"}, {Target: "Dockerfile"}, {Target: ""}}}, want: "Dockerfile, yarn.lock"},
		{name: "decoded targets", report: map[string]any{"ArtifactName": 123, "Results": []any{nil, map[string]any{"Target": "yarn.lock"}, map[string]any{"Target": "Dockerfile"}, map[string]any{"Target": "yarn.lock"}, map[string]any{"Target": 42}}}, want: "yarn.lock, Dockerfile"},
		{name: "whitespace artifact", report: map[string]any{"ArtifactName": " \n", "Results": []any{map[string]any{"Target": " Dockerfile "}}}, want: "Dockerfile"},
		{name: "single line", report: util.TrivyReport{ArtifactName: " repo\nname\r "}, want: "repo name"},
		{name: "missing metadata", report: map[string]any{}, want: "unknown (report contains no artifact name or targets)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reportSource(tt.report); got != tt.want {
				t.Fatalf("reportSource() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProviderNtfy_InvalidURL(t *testing.T) {
	for _, topicURL := range []string{
		"", "://invalid", "/topic", "ftp://example.com/topic", "https:///topic",
		"https://example.com", "https://example.com/", "https://example.com///",
		"https://user:password@example.com/topic", "https://example.com/topic#fragment",
		"https://example.com/topic#", "https://example.com/%zz",
	} {
		t.Run(topicURL, func(t *testing.T) {
			t.Setenv("NTFY_URL", topicURL)
			t.Setenv("NTFY_TOKEN", "secret-token")
			err := New().Notify(provider.NotificationPayload{TrivyReport: util.TrivyReport{}})
			if err == nil || !strings.Contains(err.Error(), "NTFY_URL") {
				t.Fatalf("expected configuration error, got %v", err)
			}
			assertSafeError(t, err, topicURL, "secret-token", "password")
		})
	}
}

func TestProviderNtfy_InvalidReport(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("invalid report must not send a request")
	}))
	defer ts.Close()
	t.Setenv("NTFY_URL", ts.URL+"/topic")
	for _, report := range []any{nil, "invalid", 42} {
		if err := New().Notify(provider.NotificationPayload{TrivyReport: report}); err == nil || !strings.Contains(err.Error(), "invalid report type") {
			t.Fatalf("expected statistics error, got %v", err)
		}
	}
}

func TestProviderNtfy_HTTPFailures(t *testing.T) {
	for _, status := range []int{301, 302, 307, 400, 401, 403, 429, 500, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			redirected := false
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				redirected = true
			}))
			defer target.Close()
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", target.URL+"/redirect")
				w.WriteHeader(status)
				_, _ = io.WriteString(w, "sensitive-response secret-token")
			}))
			defer ts.Close()
			topicURL := ts.URL + "/private-topic"
			t.Setenv("NTFY_URL", topicURL)
			t.Setenv("NTFY_TOKEN", "secret-token")
			err := New().Notify(provider.NotificationPayload{TrivyReport: util.TrivyReport{}})
			// Check the numeric code, rather than potentially sensitive server status text.
			want := "ntfy notification failed with HTTP status " + strconv.Itoa(status)
			if err == nil || err.Error() != want {
				t.Fatalf("error = %v, want %q", err, want)
			}
			assertSafeError(t, err, topicURL, "private-topic", "secret-token", "sensitive-response")
			if redirected {
				t.Fatal("redirect was followed")
			}
		})
	}
}

func TestProviderNtfy_TransportFailure(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	topicURL := ts.URL + "/private-topic"
	ts.Close()
	t.Setenv("NTFY_URL", topicURL)
	t.Setenv("NTFY_TOKEN", "secret-token")
	err := New().Notify(provider.NotificationPayload{TrivyReport: util.TrivyReport{}})
	if err == nil || !strings.Contains(err.Error(), "failed to send ntfy") {
		t.Fatalf("expected transport error, got %v", err)
	}
	assertSafeError(t, err, topicURL, "private-topic", "secret-token")
}

func assertSafeError(t *testing.T, err error, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Errorf("error exposes sensitive data: %v", err)
		}
	}
}
