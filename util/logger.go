package util

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

type LogLevel string

const (
	InfoLevel  LogLevel = "INFO"
	WarnLevel  LogLevel = "WARN"
	ErrorLevel LogLevel = "ERROR"
	DebugLevel LogLevel = "DEBUG"
)

type Logger struct {
	component string
	logger    *log.Logger
}

// NewLogger creates a new logger instance with the specified component name
func NewLogger(component string) *Logger {
	return &Logger{
		component: component,
		logger:    log.New(os.Stdout, "", 0),
	}
}

// formatMessage formats the log message with the specified level and optional key-value pairs
func (l *Logger) formatMessage(level LogLevel, msg string, kvs ...string) string {
	timestamp := time.Now().Format(time.RFC3339)
	var baseMsg strings.Builder
	baseMsg.WriteString(fmt.Sprintf("%s\t%s\t[%s] %s", timestamp, level, l.component, msg))

	if len(kvs) > 0 {
		for i := 0; i < len(kvs); i += 2 {
			if i+1 < len(kvs) {
				baseMsg.WriteString(fmt.Sprintf("\t%s=%q", kvs[i], kvs[i+1]))
			}
		}
	}

	return baseMsg.String()
}

// Info logs an info level message
func (l *Logger) Info(msg string, kvs ...string) {
	l.logger.Println(l.formatMessage(InfoLevel, msg, kvs...))
}

// Warn logs a warning level message
func (l *Logger) Warn(msg string, kvs ...string) {
	l.logger.Println(l.formatMessage(WarnLevel, msg, kvs...))
}

// Error logs an error level message
func (l *Logger) Error(msg string, kvs ...string) {
	l.logger.Println(l.formatMessage(ErrorLevel, msg, kvs...))
}

// Debug logs a debug level message
func (l *Logger) Debug(msg string, kvs ...string) {
	l.logger.Println(l.formatMessage(DebugLevel, msg, kvs...))
}

// Fatal logs an error level message and exits with code 1
func (l *Logger) Fatal(msg string, kvs ...string) {
	l.logger.Println(l.formatMessage(ErrorLevel, msg, kvs...))
	os.Exit(1)
}
