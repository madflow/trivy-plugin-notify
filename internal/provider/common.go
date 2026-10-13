package provider

import "github.com/madflow/trivy-plugin-notify/internal/environment"

type NotificationPayload = struct {
	EnvironmentCi environment.EnvironmentCi
	TrivyReport   any
}
