package registry

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ACRUser is the user name that goes with an Azure Container Registry
// refresh token, as `az acr login` uses it.
const ACRUser = "00000000-0000-0000-0000-000000000000"

// ACRLogin trades an Azure AD access token for a refresh token of this
// Azure Container Registry (its POST /oauth2/exchange) and logs in with it
// from now on. tenant may be "". The exchange goes the client's way (its
// --via path and TLS settings), and only over https with the certificate
// checked: the Azure token is good for the whole subscription.
func (c *Client) ACRLogin(ctx context.Context, aadToken, tenant string) error {
	if !c.CheckedTLS() {
		return errors.New("an Azure login goes to the registry only over https with its certificate checked")
	}
	form := url.Values{"grant_type": {"access_token"}, "service": {c.Base.Hostname()}, "access_token": {aadToken}}
	if tenant != "" {
		form.Set("tenant", tenant)
	}
	u := *c.Base
	u.Path, u.RawQuery = "/oauth2/exchange", ""
	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "komando")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var r struct {
		RefreshToken string `json:"refresh_token"`
		Errors       []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	_ = json.Unmarshal(body, &r)
	if resp.StatusCode != http.StatusOK || r.RefreshToken == "" {
		e := &Error{Status: resp.StatusCode, Code: "UNAUTHORIZED", Message: "the registry did not take the Azure login"}
		if resp.StatusCode == http.StatusOK {
			e.Status = http.StatusUnauthorized
		}
		if len(r.Errors) > 0 && r.Errors[0].Message != "" {
			e.Message += ": " + r.Errors[0].Message
		}
		return e
	}
	c.mu.Lock()
	c.User, c.Password, c.tokens = ACRUser, r.RefreshToken, map[string]string{}
	c.mu.Unlock()
	return nil
}
