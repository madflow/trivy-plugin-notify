package main

import (
	"testing"

	"github.com/madflow/trivy-plugin-notify/util"
)

type testPayload struct {
	ArtifactName string
}

func Test_run(t *testing.T) {
	t.Run("run", func(t *testing.T) {
		stats := util.Statistics{}
		_, err := run(testPayload{}, stats)
		if err == nil {
			t.Errorf("expected an error")
		}
	})
}
