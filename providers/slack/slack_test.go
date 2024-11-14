package slack

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_sendSlackMessage(t *testing.T) {
	t.Run("slack webhook success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" {
				t.Errorf("unexpected method: %v", r.Method)
			}

			if r.Header.Get("Content-Type") != "application/json" {
				t.Errorf("unexpected content type: %v", r.Header.Get("Content-Type"))
			}
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{ "ok": true }`)
		}))
		defer ts.Close()

		err := sendSlackMessage(ts.URL, new(bytes.Buffer))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})
}
