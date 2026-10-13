# trivy-plugin-notify

A [Trivy](https://github.com/aquasecurity/trivy) plugin for sending notifications to a one or more providers.

The currently supported providers are:

- console
- email
- slack
- ntfy
- webhook

Providers can be configured via environment variables.
Multiple providers can be configured via the `--providers` flag as a comma-separated list.

When `--send-always` is set, the plugin will send notifications even if no scan results were found.

## Installation

```shell
trivy plugin install github.com/madflow/trivy-plugin-notify
```

## Usage

```shell
trivy <target> --format json --output plugin=notify [--output-plugin-arg plugin_flags] <target_name>
```

```shell
trivy <target> -f json <target_name> | trivy notify [plugin_flags]
```

## Examples

```shell
trivy image -f json -o plugin=notify --output-plugin-arg "--providers=slack" debian:12
```

```shell
trivy image -f json debian:12 | trivy notify --providers=slack
```

```shell
trivy image -f json debian:12 | trivy notify --providers=slack,webhook
```

```shell
trivy image -f json golang:alpine | trivy notify --providers=slack,webhook --send-always
```

## Providers

### Console

This provider can be used to pretty-print the results in the console, mainly for debugging purposes.

### Email

This provider can be used to send notifications via email using SMTP.

Currently, only `vuln` scanning results are supported. If there are no vulnerabilities found in the scan report, sending emails will be skipped.

#### Requirements

- Set up an SMTP server and obtain the necessary credentials
- Configure the required environment variables with your SMTP and email details

#### Environment Variables

```shell
export EMAIL_DSN="smtps://user:password@smtp.example.com:465"
export EMAIL_FROM="from@example.com"
export EMAIL_TO="to@example.com"
```

`EMAIL_DSN`: The SMTP connection string in the format:

```shell
smtp://<user>:<password>@<host>:<port> or smtps://<user>:<password>@<host>:<port>
```

Example:

    For plain SMTP: smtp://user:password@smtp.example.com:587
    For SMTPS (TLS): smtps://user:password@smtp.example.com:465

Parameters:

- `<user>`: The username or email address used for SMTP authentication
- `<password>`: The password for the SMTP server
- `<host>`: The hostname of the SMTP server (e.g., smtp.example.com)
- `<port>`: The port used by the SMTP server (e.g., 587 for SMTP, 465 for SMTPS)

`EMAIL_FROM`: The sender's email address (e.g., from@example.com).

`EMAIL_TO`: The recipient's email address(es). Multiple recipients can be specified, separated by commas (e.g., to@example.com, another@example.com).

### Slack

This provider can be used to send notifications to a Slack channel through an HTTP webhook.

Currently only `vuln` scanning results are supported. If there are no vulnerabilities found in the scan report, sending Slack notifications will be skipped.

#### Requirements

- Set up a Slack Incoming Webhook.
- Set the environment variable `SLACK_WEBHOOK` with your webhook URL.

```shell
export SLACK_WEBHOOK="https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
```

#### Environment Variables

- `SLACK_WEBHOOK`: The URL of the Slack Incoming Webhook to which the message will be sent.

#### Examples

```shell
trivy image -f json debian:12 | trivy notify --providers=slack
```

### ntfy

This provider publishes a compact plain-text summary to [ntfy](https://ntfy.sh), including the scan source and counts for vulnerabilities, secrets, misconfigurations, licenses, packages, and their total. It supports hosted and self-hosted ntfy servers.

The source comes from the report's `ArtifactName` (such as a directory path or image name), falling back to unique result targets when unavailable. If neither is present, the source is explicitly marked unknown. In supported CI environments, the message also includes the CI provider and available project, ref, and URL. Local placeholder CI metadata is omitted.

#### Environment Variables

- `NTFY_URL` (required): The full HTTP(S) topic URL, including the topic path. Embedded credentials and URL fragments are not allowed.
- `NTFY_TOKEN` (optional): An access token sent using bearer authentication. Do not embed tokens in the URL.

#### Examples

Hosted ntfy:

```shell
export NTFY_URL="https://ntfy.sh/my-trivy-topic"
trivy image -f json debian:12 | trivy notify --providers=ntfy
```

Self-hosted ntfy with authentication:

```shell
export NTFY_URL="https://ntfy.example.com/trivy"
export NTFY_TOKEN="your-access-token"
trivy image -f json debian:12 | trivy notify --providers=ntfy,webhook
```

The combined example also requires the webhook provider's configuration.

Reports with a zero total are skipped unless `--send-always` is set. Reports containing only secrets, misconfigurations, licenses, or packages are eligible; the total includes packages and licenses, not just security findings. With `--send-always`, empty reports produce a summary with zero counts.

Messages use the fixed title `Trivy scan results`, a 30-second timeout, and no redirects or retries. Any 2xx response indicates success.

Public-topic names are **not authentication**. Use protected topics and access tokens for sensitive notifications, and HTTPS to protect tokens in transit.

### Webhook

This provider allows sending JSON-formatted messages to a specified URL endpoint using HTTP methods like `POST` or `GET`. It is used to send a `types.Report` (from `github.com/aquasecurity/trivy/pkg/types`) payload to an endpoint specified by an environment variable.

#### Requirements

- Set up an environment variable `WEBHOOK_ENDPOINT` with your webhook URL.

```shell
export WEBHOOK_ENDPOINT="https://example.com/webhook"
```

#### Environment Variables

- `WEBHOOK_ENDPOINT`: The URL of the webhook to which the message will be sent.
- `WEBHOOK_METHOD`: The HTTP method used to send the message. Defaults to `POST`.

#### Examples

```shell
trivy image -f json debian:12 | trivy notify --providers=webhook
```

## CI/CD integration

### Gitlab

- Create CI Variable called `TRIVY_SLACK_WEBHOOK` with the URL of the Slack Incoming Webhook to which the message will be sent.

```yaml
security-scanning:
  stage: cronjobs
  image:
    name: docker.io/aquasec/trivy:latest
    entrypoint: [""]
  cache:
    paths:
      - .trivycache/
  rules:
    - if: '$CI_PIPELINE_SOURCE == "schedule"'
      when: always
    - if: '$CI_PIPELINE_SOURCE != "schedule"'
      when: never
  script:
    - trivy plugin install github.com/madflow/trivy-plugin-notify
    - trivy repo --format json --scanners vuln -o plugin=notify --output-plugin-arg "--providers=slack" --scanners secret .
  variables:
    SLACK_WEBHOOK: $TRIVY_SLACK_WEBHOOK
    TRIVY_DB_REPOSITORY: public.ecr.aws/aquasecurity/trivy-db,aquasec/trivy-db,ghcr.io/aquasecurity/trivy-db
    TRIVY_JAVA_DB_REPOSITORY: public.ecr.aws/aquasecurity/trivy-java-db,aquasec/trivy-java-db,ghcr.io/aquasecurity/trivy-java-db
```
