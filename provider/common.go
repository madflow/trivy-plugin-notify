package provider

import "github.com/madflow/trivy-plugin-notify/environment"

type NotificationPayload = struct {
	EnvironmentCi environment.EnvironmentCi
	TrivyReport   interface{}
}
