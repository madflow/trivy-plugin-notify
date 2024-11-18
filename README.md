# trivy-plugin-notify

A [Trivy](https://github.com/aquasecurity/trivy) plugin for sending notifications to a one ore more providers.

The currently supported providers are:

- Webhook
- Slack

Providers can be configured via environment variables.
Multiple providers can be configured via the `--providers` flag as a comma-separated list.

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

## Providers

### Slack

This provider can be used to send notifications to a Slack channel through an HTTP webhook.

Currently only `vuln` scanning results are supported.

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

### Webhook

The `webhook` package allows sending JSON-formatted messages to a specified URL endpoint using HTTP methods like `POST` or `GET`. It is used to send a `types.Report` (from `github.com/aquasecurity/trivy/pkg/types`) payload to an endpoint specified by an environment variable.

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
