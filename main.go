package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/madflow/trivy-plugin-notify/environment"
	"github.com/madflow/trivy-plugin-notify/provider"
	"github.com/madflow/trivy-plugin-notify/provider/console"
	"github.com/madflow/trivy-plugin-notify/provider/email"
	"github.com/madflow/trivy-plugin-notify/provider/slack"
	"github.com/madflow/trivy-plugin-notify/provider/webhook"
	"github.com/madflow/trivy-plugin-notify/util"
)

// LogMessage represents a message with a log level
type LogMessage struct {
	Level   string // info, error, etc.
	Message string
}

func main() {
	logger := util.NewLogger("trivy-plugin-notify")
	var report any
	if err := json.NewDecoder(os.Stdin).Decode(&report); err != nil {
		logger.Fatal("Failed to read stdin. please make sure to use the --json flag")
	}
	stats, err := util.CollectStatistics(report)
	if err != nil {
		logger.Fatal(fmt.Sprintf("An error occurred: %s", err))
	}
	// log the stats
	logger.Info(fmt.Sprintf("Statistics: %+v", stats))
	logMsg, err := run(report, stats)
	// Always log the message if it exists
	if logMsg != nil {
		if logMsg.Level == "error" {
			logger.Error(logMsg.Message)
		} else {
			logger.Info(logMsg.Message)
		}
	}
	// Handle error separately
	if err != nil {
		logger.Fatal(fmt.Sprintf("%s", err))
	}
}

func run(report any, stats util.Statistics) (*LogMessage, error) {
	providersFlag := flag.String("providers", "", "Notification providers (comma separated)")
	sendAlways := flag.Bool("send-always", false, "Always send notifications. Even when there are no results.")
	flag.Parse()

	if *providersFlag == "" {
		return &LogMessage{Level: "error", Message: "No notification providers specified."}, errors.New("please specify at least one notification provider")
	}

	providersArg := strings.Split(*providersFlag, ",")
	for _, provider := range providersArg {
		if err := isSupported(provider); err != nil {
			return &LogMessage{Level: "error", Message: fmt.Sprintf("Unsupported provider: %s", provider)}, err
		}
	}

	// Check if the "Results" key is missing in the report
	// If the the flag is set to false, we don't send empty results
	if !*sendAlways && stats.Total == 0 {
		return &LogMessage{Level: "info", Message: "No scan results found in the report and send-always is false. Skipping all notifications."}, nil
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
				return &LogMessage{Level: "error", Message: fmt.Sprintf("Console provider failed: %s", err)}, err
			}
		case "email":
			if stats.Vulnerabilities == 0 && !*sendAlways {
				return &LogMessage{Level: "info", Message: "No vulnerabilities in the report found, skipping email notification."}, nil
			}
			emailProvider := email.New()
			if err := emailProvider.Notify(providersPayload); err != nil {
				return &LogMessage{Level: "error", Message: fmt.Sprintf("Email provider failed: %s", err)}, err
			}
		case "slack":
			if stats.Vulnerabilities == 0 && !*sendAlways {
				return &LogMessage{Level: "info", Message: "No vulnerabilities found in the report, skipping slack notification."}, nil
			}
			slackProvider := slack.New()
			if err := slackProvider.Notify(providersPayload); err != nil {
				return &LogMessage{Level: "error", Message: fmt.Sprintf("Slack provider failed: %s", err)}, err
			}
		case "webhook":
			webhookProvider := webhook.New()
			if err := webhookProvider.Notify(providersPayload); err != nil {
				return &LogMessage{Level: "error", Message: fmt.Sprintf("Webhook provider failed: %s", err)}, err
			}
		}
	}

	return &LogMessage{Level: "info", Message: "All notifications sent successfully."}, nil
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
