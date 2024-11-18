package testhelper

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func SetupMockServer(t *testing.T, capturedRequest *[]byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read request body: %v", err)
		}
		*capturedRequest = body
		w.Header().Set("Content-Type", "application/json")
		_, err = io.WriteString(w, `{ "ok": true }`)
		if err != nil {
			t.Errorf("failed to write response: %v", err)
		}
	}))
}
