package ntfy

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/madflow/trivy-plugin-notify/provider"
	"github.com/madflow/trivy-plugin-notify/util"
)

type ProviderNtfy struct{}

func New() *ProviderNtfy {
	return &ProviderNtfy{}
}

func (p *ProviderNtfy) Name() string {
	return "ntfy"
}

func (p *ProviderNtfy) Notify(data provider.NotificationPayload) error {
	topicURL := os.Getenv("NTFY_URL")
	if topicURL == "" {
		return errors.New("NTFY_URL environment variable is not set")
	}
	parsed, err := url.Parse(topicURL)
	if err != nil || parsed == nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Hostname() == "" || strings.Trim(parsed.Path, "/ ") == "" || parsed.User != nil || strings.Contains(topicURL, "#") {
		return errors.New("NTFY_URL must be an absolute HTTP(S) topic URL without credentials or fragments")
	}

	stats, err := util.CollectStatistics(data.TrivyReport)
	if err != nil {
		return err
	}
	body := fmt.Sprintf("Source: %s\n", reportSource(data.TrivyReport))
	ci := data.EnvironmentCi
	if ci.Provider != "" && ci.Provider != "local" {
		body += fmt.Sprintf("CI provider: %s\n", singleLine(ci.Provider))
		for _, field := range []struct{ label, value string }{
			{"Project", ci.Project}, {"Ref", ci.Ref}, {"URL", ci.Url},
		} {
			if value := singleLine(field.value); value != "" {
				body += fmt.Sprintf("%s: %s\n", field.label, value)
			}
		}
	}
	body += fmt.Sprintf("\nVulnerabilities: %d\nSecrets: %d\nMisconfigurations: %d\nLicenses: %d\nPackages: %d\nTotal: %d\n",
		stats.Vulnerabilities, stats.Secrets, stats.Misconfigurations, stats.Licenses, stats.Packages, stats.Total)
	req, err := http.NewRequest(http.MethodPost, topicURL, strings.NewReader(body))
	if err != nil {
		return errors.New("failed to create ntfy request: check NTFY_URL")
	}
	req.Header.Set("Content-Type", "text/plain; charset=utf-8")
	req.Header.Set("Title", "Trivy scan results")
	if token := os.Getenv("NTFY_TOKEN"); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		// Transport errors may contain the URL or request headers; do not expose them.
		return errors.New("failed to send ntfy notification: check connectivity, TLS, and NTFY configuration")
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("ntfy notification failed with HTTP status %d", resp.StatusCode)
	}
	return nil
}

// Prefer the scan artifact; older reports can fall back to individual result targets.
func reportSource(report any) string {
	var artifact string
	var targets []string
	switch report := report.(type) {
	case util.TrivyReport:
		artifact = report.ArtifactName
		for _, result := range report.Results {
			targets = append(targets, result.Target)
		}
	case map[string]any:
		artifact, _ = report["ArtifactName"].(string)
		results, _ := report["Results"].([]any)
		for _, result := range results {
			if result, ok := result.(map[string]any); ok {
				target, _ := result["Target"].(string)
				targets = append(targets, target)
			}
		}
	}
	if artifact = singleLine(artifact); artifact != "" {
		return artifact
	}
	var unique []string
	seen := make(map[string]bool)
	for _, target := range targets {
		if target = singleLine(target); target != "" && !seen[target] {
			seen[target] = true
			unique = append(unique, target)
		}
	}
	if len(unique) > 0 {
		return strings.Join(unique, ", ")
	}
	return "unknown (report contains no artifact name or targets)"
}

func singleLine(value string) string {
	return strings.TrimSpace(strings.NewReplacer("\r", " ", "\n", " ").Replace(value))
}
