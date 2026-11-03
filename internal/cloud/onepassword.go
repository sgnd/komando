package cloud

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// ErrNoConnect: op:// needs a 1Password Connect server (OP_CONNECT_HOST).
var ErrNoConnect = errors.New("1Password Connect is not set up (OP_CONNECT_HOST and OP_CONNECT_TOKEN)")

// OnePassword reads op://VAULT/ITEM[/SECTION]/FIELD from a 1Password Connect
// server, through its documented REST API: OP_CONNECT_HOST is the server,
// OP_CONNECT_TOKEN its access token. Vaults and items are matched by name
// or id, fields by label or id (and section when given).
func OnePassword(ctx context.Context, ref string) (string, error) {
	host := strings.TrimRight(os.Getenv("OP_CONNECT_HOST"), "/")
	token := os.Getenv("OP_CONNECT_TOKEN")
	if host == "" || token == "" {
		return "", ErrNoConnect
	}
	parts := strings.Split(strings.TrimPrefix(ref, "op://"), "/")
	if len(parts) < 3 || len(parts) > 4 {
		return "", fmt.Errorf("op:// references are op://VAULT/ITEM/FIELD or op://VAULT/ITEM/SECTION/FIELD")
	}
	vaultName, itemName, section, field := parts[0], parts[1], "", parts[len(parts)-1]
	if len(parts) == 4 {
		section = parts[2]
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	get := func(path string, v any) error {
		req, err := http.NewRequestWithContext(ctx, "GET", host+path, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return fmt.Errorf("1password connect: %v", err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
		if resp.StatusCode != http.StatusOK {
			var e struct{ Message string }
			_ = json.Unmarshal(b, &e)
			return fmt.Errorf("1password connect: %s %s", resp.Status, e.Message)
		}
		return json.Unmarshal(b, v)
	}
	type named struct{ ID, Name, Title string }
	pick := func(list []named, want, kind string) (string, error) {
		for _, x := range list {
			if x.ID == want || x.Name == want || x.Title == want {
				return x.ID, nil
			}
		}
		return "", fmt.Errorf("1password connect: no %s %q", kind, want)
	}
	var vaults []named
	if err := get("/v1/vaults?filter="+url.QueryEscape(`name eq "`+vaultName+`"`), &vaults); err != nil {
		return "", err
	}
	if len(vaults) == 0 { // maybe an id
		var all []named
		if err := get("/v1/vaults", &all); err != nil {
			return "", err
		}
		vaults = all
	}
	vid, err := pick(vaults, vaultName, "vault")
	if err != nil {
		return "", err
	}
	var items []named
	if err := get("/v1/vaults/"+vid+"/items?filter="+url.QueryEscape(`title eq "`+itemName+`"`), &items); err != nil {
		return "", err
	}
	if len(items) == 0 {
		if err := get("/v1/vaults/"+vid+"/items", &items); err != nil {
			return "", err
		}
	}
	iid, err := pick(items, itemName, "item")
	if err != nil {
		return "", err
	}
	var item struct {
		Fields []struct {
			ID, Label, Value string
			Section          *struct{ ID, Label string }
		}
	}
	if err := get("/v1/vaults/"+vid+"/items/"+iid, &item); err != nil {
		return "", err
	}
	for _, f := range item.Fields {
		if f.ID != field && !strings.EqualFold(f.Label, field) {
			continue
		}
		if section != "" && (f.Section == nil || f.Section.ID != section && !strings.EqualFold(f.Section.Label, section)) {
			continue
		}
		return f.Value, nil
	}
	return "", fmt.Errorf("1password connect: item %q has no field %q", itemName, field)
}
