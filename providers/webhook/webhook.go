package webhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"

	"github.com/madflow/trivy-plugin-notify/report"
)

var allowedMethods = map[string]bool{
	"POST": true,
	"GET":  true,
}

func New() *ProviderWebhook {
	return &ProviderWebhook{}
}

type ProviderWebhook struct{}

func (p *ProviderWebhook) Name() string {
	return "slack"
}

func (p *ProviderWebhook) Notify(data report.Report) error {
	webhookUrl := os.Getenv("WEBHOOK_URL")
	if webhookUrl == "" {
		return errors.New("WEBHOOK_URL environment variable is not set")
	}

	webhookMethod, webhookMethodExists := os.LookupEnv("WEBHOOK_METHOD")
	if !webhookMethodExists || webhookMethod == "" {
		webhookMethod = "POST"
	}

	if !allowedMethods[webhookMethod] {
		return errors.New("method not allowed")
	}

	err := sendWebhookMessage(webhookUrl, webhookMethod, data)
	if err != nil {
		return err
	}

	return nil
}

func sendWebhookMessage(webhookUrl string, method string, data report.Report) error {
	if method == "GET" {
		// when the webhook method is GET, we send the data as query parameters
		// the data has to be encoded to JSON before
		dataJson, err := json.Marshal(data)
		if err != nil {
			return err
		}
		parsedUrl, err := url.Parse(webhookUrl)
		if err != nil {
			return err
		}
		query := parsedUrl.Query()
		query.Add("vulnerabilities", string(dataJson))
		parsedUrl.RawQuery = query.Encode()
		webhookUrl = parsedUrl.String()
	}

	httpClient := &http.Client{}

	dataJson, err := json.Marshal(data)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(method, webhookUrl, bytes.NewBuffer(dataJson))
	if err != nil {
		return err
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}

	if resp.StatusCode != 200 {
		return errors.New("failed to send message")
	}

	body := resp.Body
	defer body.Close()

	return nil
}
