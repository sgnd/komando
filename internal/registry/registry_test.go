package registry

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The catalog comes in pages joined by the Link header; all of them count.
func TestCatalogFollowsPages(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v2/_catalog" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Get("last") == "" {
			w.Header().Set("Link", `</v2/_catalog?last=b&n=2>; rel="next"`)
			fmt.Fprint(w, `{"repositories":["a","b"]}`)
			return
		}
		fmt.Fprint(w, `{"repositories":["c"]}`)
	}))
	defer srv.Close()
	c := New(strings.TrimPrefix(srv.URL, "http://"), TLS{Plain: true}, "", "", nil)
	got, err := c.Catalog(context.Background(), 100)
	if err != nil || strings.Join(got, ",") != "a,b,c" {
		t.Fatalf("catalog = %v, %v; want a,b,c", got, err)
	}
	if got, _ := c.Catalog(context.Background(), 2); len(got) != 2 {
		t.Errorf("limit 2 returned %v", got)
	}
}
