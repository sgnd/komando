package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// APIModel asks a provider's messages API for the next step. It is the
// only code of the harness that spends money, and it runs only when a
// person has said yes to the cost. Its key comes from the environment of
// the CI job or the lab shell (SOP_API_KEY) and from nowhere else: the
// package opens no file for it (TestNoCodePathReadsAKeyFile).
type APIModel struct {
	model, key, url string
	client          *http.Client
}

// defaultURL is the provider's messages endpoint; SOP_API_URL replaces it
// (a local test server, a proxy).
const defaultURL = "https://api.anthropic.com/v1/messages"

// NewAPIModel makes the adapter for model. getenv is os.Getenv in the real
// run and a table in tests.
func NewAPIModel(model string, getenv func(string) string) (*APIModel, error) {
	key := getenv("SOP_API_KEY")
	if key == "" {
		return nil, ErrNoKey
	}
	url := getenv("SOP_API_URL")
	if url == "" {
		url = defaultURL
	}
	return &APIModel{model: model, key: key, url: url, client: &http.Client{Timeout: 2 * time.Minute}}, nil
}

type apiTurn struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type apiRequest struct {
	Model     string    `json:"model"`
	MaxTokens int       `json:"max_tokens"`
	System    string    `json:"system"`
	Messages  []apiTurn `json:"messages"`
	Tools     []apiTool `json:"tools"`
}

type apiTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

type apiResponse struct {
	Content []struct {
		Type  string `json:"type"`
		Text  string `json:"text"`
		Name  string `json:"name"`
		Input struct {
			Command  string `json:"command"`
			Question string `json:"question"`
		} `json:"input"`
	} `json:"content"`
	Usage struct {
		In  int `json:"input_tokens"`
		Out int `json:"output_tokens"`
	} `json:"usage"`
}

const systemText = "You work in a lab shell. Do the task with komando commands only. Use the shell tool to run one komando command at a time, and ask_person when a command stops and needs the user's yes. Say you are done when the task is done."

// Next sends the conversation and reads the model's one tool call.
func (a *APIModel) Next(ctx context.Context, turns []Turn) (Step, Usage, error) {
	req := apiRequest{Model: a.model, MaxTokens: 2048, System: systemText, Tools: tools()}
	for _, t := range turns {
		role := t.Role
		if role == "tool" {
			role = "user"
		}
		req.Messages = append(req.Messages, apiTurn{Role: role, Content: t.Text})
	}
	body, err := json.Marshal(req)
	if err != nil {
		return Step{}, Usage{}, err
	}
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, a.url, bytes.NewReader(body))
	if err != nil {
		return Step{}, Usage{}, err
	}
	hr.Header.Set("content-type", "application/json")
	hr.Header.Set("x-api-key", a.key)
	hr.Header.Set("anthropic-version", "2023-06-01")
	resp, err := a.client.Do(hr)
	if err != nil {
		return Step{}, Usage{}, fmt.Errorf("model call failed: %w", errors.Unwrap(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Step{}, Usage{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Step{}, Usage{}, fmt.Errorf("model call: status %d", resp.StatusCode) // never the body: it may echo the request
	}
	var out apiResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return Step{}, Usage{}, fmt.Errorf("model call: %w", err)
	}
	use := Usage{In: out.Usage.In, Out: out.Usage.Out}
	for _, c := range out.Content {
		switch {
		case c.Type == "tool_use" && c.Name == "shell":
			return Step{Kind: KindRun, Argv: strings.Fields(c.Input.Command)}, use, nil
		case c.Type == "tool_use" && c.Name == "ask_person":
			return Step{Kind: KindAsk, Text: c.Input.Question}, use, nil
		case c.Type == "text" && strings.TrimSpace(c.Text) != "":
			return Step{Kind: KindSay, Text: c.Text}, use, nil
		}
	}
	return Step{Kind: KindGiveUp, Text: "the model gave no step"}, use, nil
}

func tools() []apiTool {
	obj := func(prop, desc string) map[string]any {
		return map[string]any{"type": "object", "properties": map[string]any{prop: map[string]any{"type": "string", "description": desc}}, "required": []string{prop}}
	}
	return []apiTool{
		{Name: "shell", Description: "Run one komando command in the lab.", InputSchema: obj("command", "the komando command line")},
		{Name: "ask_person", Description: "Ask the user a question, for example for their yes.", InputSchema: obj("question", "what to ask")},
	}
}
