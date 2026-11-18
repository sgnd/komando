package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The token service decides how much it sends: a reply larger than any
// token is an error, not read to its end.
func TestTokenReplyIsCapped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"token":"`)
		chunk := strings.Repeat("a", 64<<10)
		for range 64 { // 4 MiB of one string
			if _, err := fmt.Fprint(w, chunk); err != nil {
				return
			}
		}
		fmt.Fprint(w, `"}`)
	}))
	defer srv.Close()
	c := New(strings.TrimPrefix(srv.URL, "http://"), TLS{Plain: true}, "", "", nil)
	tok, err := c.token(context.Background(), `bearer realm="`+srv.URL+`/token",service="r"`, "")
	if err == nil {
		t.Errorf("a %d-byte token was accepted", len(tok))
	}
	// an ordinary reply still works
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"t0k"}`)
	}))
	defer ok.Close()
	if tok, err := c.token(context.Background(), `bearer realm="`+ok.URL+`/token"`, ""); err != nil || tok != "t0k" {
		t.Errorf("token: %q %v", tok, err)
	}
}
