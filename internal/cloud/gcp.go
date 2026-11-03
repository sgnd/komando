package cloud

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// gcpSecretEndpoint is Secret Manager's REST address; tests point it at a
// local server.
var gcpSecretEndpoint = "https://secretmanager.googleapis.com"

// gcpCredentials finds Google application-default credentials: the
// GOOGLE_APPLICATION_CREDENTIALS file, the well-known file in the gcloud
// folder, or the metadata server on Google Cloud. Tests replace it.
var gcpCredentials = func(ctx context.Context) (*google.Credentials, error) {
	return google.FindDefaultCredentials(ctx, "https://www.googleapis.com/auth/cloud-platform")
}

// ErrGCPLogin is wrapped by errors that credentials fix.
var ErrGCPLogin = errors.New("google cloud credentials required")

// GCPSecret reads the latest version of a Secret Manager secret. name is a
// secret id (project from project, the credentials or the gcloud config),
// or a full projects/P/secrets/S[/versions/V] name.
func GCPSecret(ctx context.Context, name, project string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	creds, err := gcpCredentials(ctx)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGCPLogin, err)
	}
	res := name
	if !strings.HasPrefix(name, "projects/") {
		project = firstOf(project, creds.ProjectID, os.Getenv("GOOGLE_CLOUD_PROJECT"), os.Getenv("CLOUDSDK_CORE_PROJECT"), gcloudProject())
		if project == "" {
			return "", errors.New("no Google Cloud project: write gcp-sm:NAME@PROJECT or set GOOGLE_CLOUD_PROJECT")
		}
		res = "projects/" + project + "/secrets/" + name
	}
	if !strings.Contains(res, "/versions/") {
		res += "/versions/latest"
	}
	req, err := http.NewRequestWithContext(ctx, "GET", gcpSecretEndpoint+"/v1/"+escapePath(res)+":access", nil)
	if err != nil {
		return "", err
	}
	resp, err := oauth2.NewClient(ctx, creds.TokenSource).Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrGCPLogin, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error struct{ Message, Status string } `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		return "", fmt.Errorf("secret manager: %s (%s)", firstOf(e.Error.Message, resp.Status), firstOf(e.Error.Status, resp.Status))
	}
	var r struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return "", fmt.Errorf("secret manager: %w", err)
	}
	b, err := base64.StdEncoding.DecodeString(r.Payload.Data)
	if err != nil {
		return "", fmt.Errorf("secret manager: %w", err)
	}
	return string(b), nil
}

// gcloudProject is core/project from the active gcloud configuration file,
// read directly (gcloud itself is not needed).
func gcloudProject() string {
	dir := os.Getenv("CLOUDSDK_CONFIG")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return ""
		}
		dir = filepath.Join(home, ".config", "gcloud")
	}
	active := "default"
	if b, err := os.ReadFile(filepath.Join(dir, "active_config")); err == nil && strings.TrimSpace(string(b)) != "" {
		active = strings.TrimSpace(string(b))
	}
	b, err := os.ReadFile(filepath.Join(dir, "configurations", "config_"+active))
	if err != nil {
		return ""
	}
	section := ""
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line[1 : len(line)-1]
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && section == "core" && strings.TrimSpace(k) == "project" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func escapePath(p string) string {
	parts := strings.Split(p, "/")
	for i, s := range parts {
		parts[i] = url.PathEscape(s)
	}
	return strings.Join(parts, "/")
}

func firstOf(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
