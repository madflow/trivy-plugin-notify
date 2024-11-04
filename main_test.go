package main

import (
	"testing"

	"github.com/madflow/trivy-plugin-notify/report"
)

func Test_run(t *testing.T) {
	t.Run("run", func(t *testing.T) {
		err := run(report.Report{})
		if err == nil {
			t.Errorf("expected an error")
		}
	})
}
