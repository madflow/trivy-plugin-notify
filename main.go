package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/madflow/trivy-plugin-notify/environment"
	"github.com/madflow/trivy-plugin-notify/providers"
	"github.com/madflow/trivy-plugin-notify/providers/email"
	"github.com/madflow/trivy-plugin-notify/providers/slack"
	"github.com/madflow/trivy-plugin-notify/providers/webhook"
)

func main() {
	var report interface{}
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		log.Fatalf("failed to read stdin. please make sure to use the --json flag")
	}
	if err := run(report); err != nil {
		log.Fatalf("An error occurred: %s", err)
	}
}

func run(report interface{}) error {
	providersFlag := flag.String("providers", "", "Notification providers (comma separated)")
	flag.Parse()

	if *providersFlag == "" {
		return errors.New("please specify at least one notification provider")
	}

	providersArg := strings.Split(*providersFlag, ",")
	for _, provider := range providersArg {
		if err := isSupported(provider); err != nil {
			fmt.Println(err)
			return err
		}
	}

	providersPayload := providers.NotificationPayload{
		EnvironmentCi: environment.DetectEnvironmentCi(),
		TrivyReport:   report,
	}

	// Notify the providers
	for _, provider := range providersArg {
		switch provider {
		case "email":
			emailProvider := email.New()
			if err := emailProvider.Notify(providersPayload); err != nil {
				fmt.Println(err)
				return err
			}
		case "slack":
			slackProvider := slack.New()
			if err := slackProvider.Notify(providersPayload); err != nil {
				fmt.Println(err)
				return err
			}
		case "webhook":
			webhookProvider := webhook.New()
			if err := webhookProvider.Notify(providersPayload); err != nil {
				fmt.Println(err)
				return err
			}
		}
	}

	return nil
}

func isSupported(provider string) error {
	switch provider {
	case "email":
		return nil
	case "slack":
		return nil
	case "webhook":
		return nil
	}
	return fmt.Errorf("provider %s is not supported", provider)
}
