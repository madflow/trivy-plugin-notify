package report

type Report struct {
	ArtifactName string
	Results      Results `json:",omitempty"`
}

type Results []Result

type Result struct {
	Class           string
	Type            string
	Vulnerabilities []DetectedVulnerability
}

type DetectedVulnerability struct {
	VulnerabilityID  string   `json:",omitempty"`
	VendorIDs        []string `json:",omitempty"`
	PkgID            string   `json:",omitempty"`
	PkgName          string   `json:",omitempty"`
	PkgPath          string   `json:",omitempty"`
	InstalledVersion string   `json:",omitempty"`
	FixedVersion     string   `json:",omitempty"`
	PrimaryURL       string   `json:",omitempty"`
}
