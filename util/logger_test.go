package util

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger("test-component")
	if logger.component != "test-component" {
		t.Errorf("Expected component to be 'test-component', got %s", logger.component)
	}
	if logger.logger == nil {
		t.Error("Expected logger to not be nil")
	}
}

func TestLoggerFormatMessage(t *testing.T) {
	logger := NewLogger("test")
	msg := "test message"
	formatted := logger.formatMessage(InfoLevel, msg)

	// Check basic message structure
	if !strings.Contains(formatted, "INFO") {
		t.Error("Expected message to contain log level 'INFO'")
	}
	if !strings.Contains(formatted, "[test]") {
		t.Error("Expected message to contain component '[test]'")
	}
	if !strings.Contains(formatted, msg) {
		t.Error("Expected message to contain the test message")
	}

	// Test with key-value pairs
	formattedWithKV := logger.formatMessage(InfoLevel, msg, "key1", "value1", "key2", "value2")
	if !strings.Contains(formattedWithKV, "key1=\"value1\"") {
		t.Error("Expected message to contain key-value pair 'key1=\"value1\"'")
	}
	if !strings.Contains(formattedWithKV, "key2=\"value2\"") {
		t.Error("Expected message to contain key-value pair 'key2=\"value2\"'")
	}
}

func TestLogLevels(t *testing.T) {
	tests := []struct {
		level    LogLevel
		logFunc  func(*Logger, string, ...string)
		expected string
	}{
		{InfoLevel, (*Logger).Info, "INFO"},
		{WarnLevel, (*Logger).Warn, "WARN"},
		{ErrorLevel, (*Logger).Error, "ERROR"},
		{DebugLevel, (*Logger).Debug, "DEBUG"},
	}

	for _, tt := range tests {
		t.Run(string(tt.level), func(t *testing.T) {
			var buf bytes.Buffer
			logger := &Logger{
				component: "test",
				logger:    log.New(&buf, "", 0),
			}

			tt.logFunc(logger, "test message")
			output := buf.String()

			if !strings.Contains(output, tt.expected) {
				t.Errorf("Expected log output to contain %s, got %s", tt.expected, output)
			}
		})
	}
}

func TestLoggerWithKeyValues(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		component: "test",
		logger:    log.New(&buf, "", 0),
	}

	logger.Info("test message", "key1", "value1", "key2", "value2")
	output := buf.String()

	expectedParts := []string{
		"key1=\"value1\"",
		"key2=\"value2\"",
		"[test]",
		"test message",
	}

	for _, part := range expectedParts {
		if !strings.Contains(output, part) {
			t.Errorf("Expected output to contain %q, got %s", part, output)
		}
	}
}
