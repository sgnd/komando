package runner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The adapter sends the key in a header, from the environment, to the URL
// the job names, and reads the model's tool call from the answer. A local
// server stands in for the provider: no network, no cost.
func TestAPIModelAgainstALocalServer(t *testing.T) {
	var gotKey, gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		gotBody = string(b[:n])
		w.Write([]byte(`{"content":[{"type":"tool_use","name":"shell","input":{"command":"komando list"}}],"usage":{"input_tokens":11,"output_tokens":3}}`))
	}))
	defer srv.Close()
	env := map[string]string{"SOP_API_KEY": "k-env", "SOP_API_URL": srv.URL}
	m, err := NewAPIModel("model-x", func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	step, usage, err := m.Next(context.Background(), []Turn{{Role: "user", Text: "list the servers"}})
	if err != nil {
		t.Fatal(err)
	}
	if step.Kind != KindRun || strings.Join(step.Argv, " ") != "komando list" {
		t.Errorf("step %+v", step)
	}
	if usage.In != 11 || usage.Out != 3 {
		t.Errorf("usage %+v", usage)
	}
	if gotKey != "k-env" || !strings.Contains(gotBody, "model-x") {
		t.Errorf("key %q body %q", gotKey, gotBody)
	}
}
