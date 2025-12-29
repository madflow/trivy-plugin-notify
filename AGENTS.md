# AGENTS.md - Trivy Plugin Notify

Guidelines for AI agents working on this Go-based Trivy notification plugin.

## Project Overview

This is a Trivy plugin that sends scan result notifications to various providers (Slack, Email, Webhook, Console). It reads JSON scan results from stdin and dispatches notifications based on configured providers.

## Build & Development Commands

```bash
# Build the binary
make build
# or: go build -o notify .

# Run all tests
make test
# or: go test -v ./...

# Run a single test
go test -v -run TestName ./path/to/package
# Example: go test -v -run Test_notify ./provider/slack

# Run tests for a specific package
go test -v ./provider/slack
go test -v ./util

# Lint code
make lint
# or: golangci-lint run

# Clean build artifacts
make clean
```

## Code Style Guidelines

### Go Version & Tooling

- Go 1.24+ (see go.mod)
- Linter: golangci-lint v2 with gofumpt formatter
- Enabled linters: bodyclose, gocritic, misspell

### Import Organization

Group imports in this order, separated by blank lines:
1. Standard library
2. External dependencies
3. Internal packages (github.com/madflow/trivy-plugin-notify/...)

```go
import (
    "bytes"
    "encoding/json"
    "os"

    "github.com/Masterminds/sprig/v3"
    "github.com/madflow/trivy-plugin-notify/provider"
)
```

### Naming Conventions

- **Packages**: lowercase, single word (e.g., `slack`, `webhook`, `util`)
- **Provider types**: `Provider<Name>` struct (e.g., `ProviderSlack`, `ProviderWebhook`)
- **Constructors**: `New()` function returning pointer to provider struct
- **Interfaces**: provider structs implement `Notify(data provider.NotificationPayload) error`
- **Test files**: `*_test.go` in same package as tested code
- **Test functions**: `Test_<functionName>` or `Test<TypeName>_<methodName>`

### Error Handling

- Return errors explicitly, do not panic in library code
- Use `errors.New()` for simple static errors
- Use `fmt.Errorf()` for dynamic error messages
- Check errors immediately after function calls
- Provider methods return `error` to caller for handling

```go
func (p *ProviderSlack) Notify(data provider.NotificationPayload) error {
    webhookUrl := os.Getenv("SLACK_WEBHOOK")
    if webhookUrl == "" {
        return errors.New("SLACK_WEBHOOK environment variable is not set")
    }
    // ...
    if err := sendSlackMessage(webhookUrl, wr); err != nil {
        return err
    }
    return nil
}
```

### Struct & Type Definitions

- Use typed structs with JSON tags for serialization
- Use `interface{}` or `any` for dynamic JSON data
- Pointer fields for optional values: `*string` for nullable strings

```go
type TrivyResult struct {
    Class           *string       `json:"Class,omitempty"`
    Vulnerabilities []interface{} `json:"Vulnerabilities,omitempty"`
    Target          string        `json:"Target,omitempty"`
}
```

### Provider Pattern

Each notification provider follows this structure:

```go
package providerName

type Provider<Name> struct{}

func New() *Provider<Name> {
    return &Provider<Name>{}
}

func (p *Provider<Name>) Name() string {
    return "providername"
}

func (p *Provider<Name>) Notify(data provider.NotificationPayload) error {
    // Implementation
}
```

### Templates

- Use `embed.FS` to embed template files
- Template files: `*.tpl` in provider package directory
- Use sprig template functions: `github.com/Masterminds/sprig/v3`

### Testing Patterns

- Use table-driven tests with `tests := []struct{...}`
- Use `testhelper` package for shared test utilities
- Use snapshot testing for complex output validation
- Test fixtures in `testdata/` directories
- Snapshots in `testdata/snapshots/`

```go
func Test_CollectStatistics(t *testing.T) {
    tests := []struct {
        name        string
        fixtureName string
    }{
        {name: "case name", fixtureName: "fixture.json"},
    }
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Test implementation
        })
    }
}
```

### Snapshot Testing

Snapshots auto-create on first run. To update snapshots, delete the snapshot file and rerun tests.

```go
testhelper.HandleSnapshot(t, snapshotFile, actualBytes)
```

### Environment Variables

Providers read configuration from environment:
- `SLACK_WEBHOOK` - Slack webhook URL
- `WEBHOOK_URL` - Generic webhook URL
- `WEBHOOK_METHOD` - HTTP method (GET/POST, default POST)
- `CI`, `GITHUB_ACTIONS`, `GITLAB_CI` - CI environment detection

### Logging

Use the `util.Logger` for consistent log output:

```go
logger := util.NewLogger("component-name")
logger.Info("message")
logger.Error("error message")
logger.Fatal("fatal error") // exits with code 1
```

### HTTP Requests

- Use `http.Client{}` for HTTP operations
- Always close response body with `defer resp.Body.Close()`
- Check for non-200 status codes

### File Organization

```
/                     # Root: main.go, go.mod, Makefile
/environment/         # CI environment detection
/provider/            # Notification providers
/provider/<name>/     # Individual provider implementations
/provider/<name>/testdata/  # Test fixtures
/util/                # Shared utilities (logger, statistics)
/testhelper/          # Test utilities (mock server, snapshots)
/testdata/            # Sample vulnerable projects for testing
```

## Commit Message Guidelines

This project uses **Conventional Commits** for release-please automation.

### Format

```
<type>: <description>

[optional body]
[optional footer(s)]
```

### Types

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation only changes
- `style`: Code style changes (formatting, whitespace)
- `refactor`: Code change that neither fixes a bug nor adds a feature
- `perf`: Performance improvements
- `test`: Adding or correcting tests
- `chore`: Build process or auxiliary tool changes

### Rules

1. Use imperative, present tense ("add feature" not "added feature")
2. Do not capitalize the first letter of the description
3. No period at the end of the description
4. Keep subject line under 80 characters
5. Never include scope in parentheses
6. When branch name is `<type>/<scope>`, use that type

### Examples

```
feat: add slack notification retry logic
fix: handle empty vulnerability arrays
docs: update README with webhook examples
chore: update golangci-lint configuration
test: add snapshot tests for email provider
```
