package console

import (
	"encoding/json"
	"fmt"

	"github.com/madflow/trivy-plugin-notify/providers"
)

func New() *ProviderConsole {
	return &ProviderConsole{}
}

type ProviderConsole struct{}

func (p *ProviderConsole) Name() string {
	return "console"
}

func (p *ProviderConsole) Notify(data providers.NotificationPayload) error {
	dataJson, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(dataJson))

	return nil
}
