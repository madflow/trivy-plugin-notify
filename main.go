package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

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

	providers := strings.Split(*providersFlag, ",")
	for _, provider := range providers {
		if err := isSupported(provider); err != nil {
			fmt.Println(err)
			return err
		}
	}

	// Notify the providers
	for _, provider := range providers {
		switch provider {
		case "slack":
			slackProvider := slack.New()
			if err := slackProvider.Notify(report); err != nil {
				fmt.Println(err)
				return err
			}
		case "webhook":
			webhookProvider := webhook.New()
			if err := webhookProvider.Notify(report); err != nil {
				fmt.Println(err)
				return err
			}
		}
	}

	return nil
}

func isSupported(provider string) error {
	switch provider {
	case "slack":
		return nil
	case "webhook":
		return nil
	}
	return fmt.Errorf("provider %s is not supported", provider)
}
