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
	"github.com/madflow/trivy-plugin-notify/provider"
	"github.com/madflow/trivy-plugin-notify/provider/console"
	"github.com/madflow/trivy-plugin-notify/provider/email"
	"github.com/madflow/trivy-plugin-notify/provider/slack"
	"github.com/madflow/trivy-plugin-notify/provider/webhook"
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
	sendAlways := flag.Bool("send-always", false, "Always send notifications. Even when there are no results.")
	flag.Parse()

	if *providersFlag == "" {
		return errors.New("please specify at least one notification provider")
	}

	// Check if the "Results" key is missing in the report
	// If the the flag is set to false, we don't send empty results
	if !*sendAlways {
		if _, ok := report.(map[string]interface{})["Results"]; !ok {
			return nil
		}
	}

	providersArg := strings.Split(*providersFlag, ",")
	for _, provider := range providersArg {
		if err := isSupported(provider); err != nil {
			return err
		}
	}

	providersPayload := provider.NotificationPayload{
		EnvironmentCi: environment.DetectEnvironmentCi(),
		TrivyReport:   report,
	}

	// Notify the providers
	for _, provider := range providersArg {
		switch provider {
		case "console":
			consoleProvider := console.New()
			if err := consoleProvider.Notify(providersPayload); err != nil {
				return err
			}
		case "email":
			emailProvider := email.New()
			if err := emailProvider.Notify(providersPayload); err != nil {
				return err
			}
		case "slack":
			slackProvider := slack.New()
			if err := slackProvider.Notify(providersPayload); err != nil {
				return err
			}
		case "webhook":
			webhookProvider := webhook.New()
			if err := webhookProvider.Notify(providersPayload); err != nil {
				return err
			}
		}
	}

	return nil
}

func isSupported(provider string) error {
	switch provider {
	case "console":
		return nil
	case "email":
		return nil
	case "slack":
		return nil
	case "webhook":
		return nil
	}
	return fmt.Errorf("provider %s is not supported", provider)
}
