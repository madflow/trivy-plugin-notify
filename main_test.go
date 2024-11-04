package main

import (
	"testing"
)

type testPayload struct {
	ArtifactName string
}

func Test_run(t *testing.T) {
	t.Run("run", func(t *testing.T) {
		err := run(testPayload{})
		if err == nil {
			t.Errorf("expected an error")
		}
	})
}
