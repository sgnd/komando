package store

import (
	"strings"
	"testing"
)

func TestUserSlug(t *testing.T) {
	tests := []struct{ name, in, want string }{
		{"plain", "root", "root"},
		{"windows domain user", `DOMAIN\admin`, "domain-admin"},
		{"user principal name", "admin@corp.local", "admin-corp-local"},
		{"dot", "deploy.bot", "deploy-bot"},
		{"empty user", "", "default"},
		{"only signs", `@\.`, "default"},
		{"runs and ends", "--a__b--", "a-b"},
		{"capitals", "Admin", "admin"},
		{"non ascii", "jürgen", "j-rgen"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := userSlug(tt.in); got != tt.want {
				t.Errorf("userSlug(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNameMaker(t *testing.T) {
	t.Run("a clash ignoring case takes -2, then -3", func(t *testing.T) {
		m := newNameMaker([]string{"Deploy-Admin"})
		if got := m.make("deploy", "admin"); got != "deploy-admin-2" {
			t.Errorf("first: %q", got)
		}
		if got := m.make("deploy", "ADMIN"); got != "deploy-admin-3" {
			t.Errorf("second: %q", got)
		}
	})
	t.Run("two users that fold to one name", func(t *testing.T) {
		m := newNameMaker(nil)
		a, b := m.make("deploy", "Admin"), m.make("deploy", "admin")
		if a != "deploy-admin" || b != "deploy-admin-2" {
			t.Errorf("got %q and %q", a, b)
		}
	})
	t.Run("a made name passes the name rule", func(t *testing.T) {
		m := newNameMaker(nil)
		for _, base := range []string{"k", "My.Key_1", strings.Repeat("x", 80)} {
			for _, user := range []string{`DOMAIN\admin`, "", strings.Repeat("u", 80)} {
				got := m.make(base, user)
				if !madeNameRe.MatchString(got) {
					t.Errorf("make(%q, %q) = %q breaks the name rule", base, user, got)
				}
			}
		}
	})
	t.Run("keep takes a name as it is and reserves it", func(t *testing.T) {
		m := newNameMaker(nil)
		if got := m.keep("prod-db"); got != "prod-db" {
			t.Errorf("keep: %q", got)
		}
		if got := m.make("prod", "db"); got != "prod-db-2" {
			t.Errorf("after keep: %q", got)
		}
	})
}
