package slack

import (
	"bytes"
	"embed"
	"errors"
	"html/template"
	"net/http"
	"os"

	"github.com/Masterminds/sprig/v3"
	"github.com/madflow/trivy-plugin-notify/providers"
)

//go:embed slack.tpl
var slackTmpl embed.FS

func New() *ProviderSlack {
	return &ProviderSlack{}
}

type ProviderSlack struct{}

func (p *ProviderSlack) Name() string {
	return "slack"
}

func (p *ProviderSlack) Notify(data providers.NotificationPayload) error {
	webhookUrl := os.Getenv("SLACK_WEBHOOK")
	if webhookUrl == "" {
		return errors.New("SLACK_WEBHOOK  environment variable is not set")
	}

	wr := new(bytes.Buffer)
	templateBuffer, err := slackTmpl.ReadFile("slack.tpl")
	if err != nil {
		return err
	}

	tpl, err := template.New("slack").Funcs(sprig.GenericFuncMap()).Parse(string(templateBuffer))

	if err != nil {
		return err
	}

	err = tpl.Execute(wr, data)

	if err != nil {
		return err
	}

	err = sendSlackMessage(webhookUrl, wr)
	if err != nil {
		return err
	}

	return nil
}

func sendSlackMessage(webhookUrl string, messageBuffer *bytes.Buffer) error {

	httpClient := &http.Client{}

	req, err := http.NewRequest("POST", webhookUrl, messageBuffer)
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New("failed to send slack message")
	}

	return nil
}
