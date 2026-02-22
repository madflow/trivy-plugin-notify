package email

import (
	"bytes"
	"crypto/tls"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"net/smtp"
	"net/url"
	"os"
	"strings"

	"github.com/Masterminds/sprig/v3"
	"github.com/madflow/trivy-plugin-notify/provider"
)

//go:embed email.tpl
var emailTmpl embed.FS

func New() *ProviderEmail {
	return &ProviderEmail{}
}

type ProviderEmail struct{}

func (p *ProviderEmail) Name() string {
	return "email"
}

func (p *ProviderEmail) Notify(data provider.NotificationPayload) error {
	dsn := os.Getenv("EMAIL_DSN")
	if dsn == "" {
		return errors.New("EMAIL_DSN is not set")
	}

	config, err := parseDSN(dsn)
	if err != nil {
		return err
	}

	emailTo := os.Getenv("EMAIL_TO")
	emailFrom := os.Getenv("EMAIL_FROM")
	if emailTo == "" || emailFrom == "" {
		return errors.New("EMAIL_TO and EMAIL_FROM must be set")
	}

	wr := new(bytes.Buffer)
	templateBuffer, err := emailTmpl.ReadFile("email.tpl")
	if err != nil {
		return err
	}

	tpl, err := template.New("email").Funcs(sprig.GenericFuncMap()).Parse(string(templateBuffer))
	if err != nil {
		return err
	}

	err = tpl.Execute(wr, data)
	if err != nil {
		return err
	}

	err = sendEmail(config, emailFrom, emailTo, wr.String())
	if err != nil {
		return err
	}

	return nil
}

type smtpConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	UseTLS   bool
}

func parseDSN(dsn string) (*smtpConfig, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "smtp" && u.Scheme != "smtps" {
		return nil, errors.New("invalid DSN: scheme must be smtp or smtps")
	}

	password, _ := u.User.Password()
	port := u.Port()
	if port == "" {
		port = "25" // Default SMTP port
		if u.Scheme == "smtps" {
			port = "465" // Default SMTPS port
		}
	}

	return &smtpConfig{
		Host:     u.Hostname(),
		Port:     port,
		User:     u.User.Username(),
		Password: password,
		UseTLS:   u.Scheme == "smtps",
	}, nil
}

func sendEmail(config *smtpConfig, from, to, message string) error {
	addr := config.Host + ":" + config.Port
	var auth smtp.Auth
	if config.User != "" && config.Password != "" {
		auth = smtp.PlainAuth("", config.User, config.Password, config.Host)
	}

	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: Security Report\r\n" +
		"\r\n" +
		message

	if config.UseTLS {
		// Establish a secure TLS connection
		tlsConfig := &tls.Config{
			ServerName: config.Host,
		}

		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return err
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, config.Host)
		if err != nil {
			return err
		}

		defer func() {
			if err := client.Quit(); err != nil {
				// Log the error or handle it as needed
				fmt.Println("Error quitting client:", err)
			}
		}()

		if auth != nil {
			if err := client.Auth(auth); err != nil {
				return err
			}
		}

		if err := client.Mail(from); err != nil {
			return err
		}

		recipients := strings.SplitSeq(to, ",")
		for recipient := range recipients {
			if err := client.Rcpt(strings.TrimSpace(recipient)); err != nil {
				return err
			}
		}

		w, err := client.Data()
		if err != nil {
			return err
		}

		_, err = w.Write([]byte(msg))
		if err != nil {
			return err
		}

		return w.Close()
	}

	// Fallback to plain SMTP
	return smtp.SendMail(addr, auth, from, strings.Split(to, ","), []byte(msg))
}
