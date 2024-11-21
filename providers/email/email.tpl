Trivy Report


{{- if .EnvironmentCi }}
CI Provider: {{ .EnvironmentCi.Provider }}  
Project: {{ .EnvironmentCi.Project }}  
Branch: {{ .EnvironmentCi.Branch }}  
URL: [Link]({{ .EnvironmentCi.Url }})
---


{{- end }}

{{- range .TrivyReport.Results }}
{{- if or (eq .Class "lang-pkgs") (eq .Class "os-pkgs") }}
Class: {{ .Class }}
{{- if (gt (len .Type) 0) }}
Type: {{ .Type }}
{{- end }}
{{- if (gt (len .Target) 0) }}
Target: {{ .Target }}
{{- end }}
{{- if kindIs "invalid" .Vulnerabilities }}

No vulnerabilities found.
{{- else if (gt (len .Vulnerabilities) 40) }}

{{ (len .Vulnerabilities) }} vulnerabilities found!
This is too many to include in this report.  
Please [install](https://aquasecurity.github.io/trivy/latest/getting-started/installation/) and [run](https://aquasecurity.github.io/trivy/latest/docs/target/container_image/) Trivy locally to see the full list.
{{- else if (eq (len .Vulnerabilities) 0) }}

No vulnerabilities found.
{{- else }}

Vulnerabilities

{{- range .Vulnerabilities }}

- {{ .Severity }}: {{ .VulnerabilityID }} ({{ .PrimaryURL }})  
- Package: `{{ .PkgName }} {{ .InstalledVersion }}`  
- {{- if kindIs "string" .FixedVersion }} Upgrade to: `{{ .FixedVersion }}`  
  {{- else }} No fixed version available.  
  {{- end }}
{{- end }}
{{- end }}
---
{{- end }}
{{- end }}
