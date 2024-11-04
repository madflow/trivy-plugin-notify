{
  "blocks": [
    {
      "type": "header",
      "text": {
        "type": "plain_text",
        "text": "Trivy report",
        "emoji": true
      }
    },
    {{- range . }}
      {{- if or (eq .Class "lang-pkgs") (eq .Class "os-pkgs") }} 
        {
          "type": "section",
          "text": {
            "type": "mrkdwn",
            "text": "*Class: {{ .Class | toString }}*"
          }
        },
        {{- if (gt (len .Type) 0) }} 
        {
          "type": "section",
          "text": {
            "type": "mrkdwn",
            "text": "*Type: {{ .Type | toString }}*"
          }
        },
        {{- end }}
        {{- if (gt (len .Vulnerabilities) 40) }}
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": ":warning: *{{ (len .Vulnerabilities) | toString }} vulnerabilities found!* \nThis is too many for Slack to render!\nPlease <https://aquasecurity.github.io/trivy/latest/getting-started/installation/|install> & <https://aquasecurity.github.io/trivy/latest/docs/target/container_image/|run> Trivy locally to see the full list."
            }
          },
        {{- else if (eq (len .Vulnerabilities) 0) }}
          {
            "type": "section",
            "text": {
              "type": "mrkdwn",
              "text": "_No vulnerabilities found_"
            }
          },
        {{- else }}
          {{- range .Vulnerabilities }}
            {
              "type": "rich_text",
              "elements": [
                {
                  "type": "rich_text_list",
                  "style": "bullet",
                  "elements": [
                    {
                      "type": "rich_text_section",
                      "elements": [
                        {
                          "type": "text",
                          "text": "{{ .Severity | toString }}: ",
                          "style": {
                            "bold": true
                          }
                        },
                        {
                          "type": "link",
                          "url": "{{ .PrimaryURL }}",
                          "text": "{{ .VulnerabilityID }}"
                        },
                        {
                          "type": "text",
                          "text": "{{ .PkgName }} v{{ .InstalledVersion }}",
                          "style": {
                            "code": true
                          }
                        },
                        {
                          "type": "text",
                          "text": "{{- if (gt (len .FixedVersion) 0) }} (upgrade to: {{ .FixedVersion | toString }}) {{- else}} (no fixed version) {{- end }}"
                        }
                      ]
                    }
                  ]
                }
              ]
            },
          {{- end }}
        {{- end }}
      {{- end }}
    {{- end }}
  ]
}
