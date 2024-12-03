package util

import "fmt"

type TrivyResult struct {
	Class             *string       `json:"Class,omitempty"`
	Licenses          []interface{} `json:"Licenses,omitempty"`
	Misconfigurations []interface{} `json:"Misconfigurations,omitempty"`
	Packages          []interface{} `json:"Packages,omitempty"`
	Secrets           []interface{} `json:"Secrets,omitempty"`
	Target            string        `json:"Target,omitempty"`
	Type              string        `json:"Type,omitempty"`
	Vulnerabilities   []interface{} `json:"Vulnerabilities,omitempty"`
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

func CollectStatistics(report interface{}) (Statistics, error) {
	var stats Statistics

	switch v := report.(type) {
	case TrivyReport:
		return collectFromReport(v), nil
	case map[string]interface{}:
		results, ok := v["Results"].([]interface{})
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

func collectFromMapResults(results []interface{}) Statistics {
	stats := Statistics{}
	for _, r := range results {
		result, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		if vulns, ok := result["Vulnerabilities"].([]interface{}); ok {
			stats.Vulnerabilities += len(vulns)
		}
		if secrets, ok := result["Secrets"].([]interface{}); ok {
			stats.Secrets += len(secrets)
		}
		if packages, ok := result["Packages"].([]interface{}); ok {
			stats.Packages += len(packages)
		}
		if misconfigs, ok := result["Misconfigurations"].([]interface{}); ok {
			stats.Misconfigurations += len(misconfigs)
		}
		if licenses, ok := result["Licenses"].([]interface{}); ok {
			stats.Licenses += len(licenses)
		}
	}
	stats.Total = stats.Vulnerabilities + stats.Secrets + stats.Packages + stats.Misconfigurations + stats.Licenses
	return stats
}
