package util

import "fmt"

type TrivyResult struct {
	Class             *string `json:"Class,omitempty"`
	Licenses          []any   `json:"Licenses,omitempty"`
	Misconfigurations []any   `json:"Misconfigurations,omitempty"`
	Packages          []any   `json:"Packages,omitempty"`
	Secrets           []any   `json:"Secrets,omitempty"`
	Target            string  `json:"Target,omitempty"`
	Type              string  `json:"Type,omitempty"`
	Vulnerabilities   []any   `json:"Vulnerabilities,omitempty"`
}

type TrivyReport struct {
	Results []TrivyResult `json:"Results,omitempty"`
}

type Statistics struct {
	Vulnerabilities   int
	Secrets           int
	Packages          int
	Misconfigurations int
	Licenses          int
	Total             int
}

func CollectStatistics(report any) (Statistics, error) {
	var stats Statistics

	switch v := report.(type) {
	case TrivyReport:
		return collectFromReport(v), nil
	case map[string]any:
		results, ok := v["Results"].([]any)
		if !ok {
			// Return zero statistics if Results is missing or invalid
			return stats, nil
		}
		return collectFromMapResults(results), nil
	default:
		return stats, fmt.Errorf("invalid report type: expected TrivyReport or compatible map, got %T", report)
	}
}

func collectFromReport(report TrivyReport) Statistics {
	stats := Statistics{}
	for _, result := range report.Results {
		if result.Vulnerabilities != nil {
			stats.Vulnerabilities += len(result.Vulnerabilities)
		}
		if result.Secrets != nil {
			stats.Secrets += len(result.Secrets)
		}
		if result.Packages != nil {
			stats.Packages += len(result.Packages)
		}
		if result.Misconfigurations != nil {
			stats.Misconfigurations += len(result.Misconfigurations)
		}
		if result.Licenses != nil {
			stats.Licenses += len(result.Licenses)
		}
	}
	stats.Total = stats.Vulnerabilities + stats.Secrets + stats.Packages + stats.Misconfigurations + stats.Licenses
	return stats
}

func collectFromMapResults(results []any) Statistics {
	stats := Statistics{}
	for _, r := range results {
		result, ok := r.(map[string]any)
		if !ok {
			continue
		}

		if vulns, ok := result["Vulnerabilities"].([]any); ok {
			stats.Vulnerabilities += len(vulns)
		}
		if secrets, ok := result["Secrets"].([]any); ok {
			stats.Secrets += len(secrets)
		}
		if packages, ok := result["Packages"].([]any); ok {
			stats.Packages += len(packages)
		}
		if misconfigs, ok := result["Misconfigurations"].([]any); ok {
			stats.Misconfigurations += len(misconfigs)
		}
		if licenses, ok := result["Licenses"].([]any); ok {
			stats.Licenses += len(licenses)
		}
	}
	stats.Total = stats.Vulnerabilities + stats.Secrets + stats.Packages + stats.Misconfigurations + stats.Licenses
	return stats
}
