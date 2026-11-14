package out

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"slices"
	"sort"
	"strings"
)

type hidden struct {
	raw, json, label string
	added            bool // by AddValue: forgotten when the next command starts (ForgetAdded)
	vault            bool // from Secrets: forgotten when they change (SetSecrets)
}

// minSecret is the shortest value hidden: shorter ones would match
// ordinary words and garble output.
const minSecret = 6

func (p *Printer) load() {
	p.hmu.RLock()
	loaded := p.loaded
	p.hmu.RUnlock()
	if loaded {
		return
	}
	p.hmu.Lock()
	defer p.hmu.Unlock()
	if p.loaded {
		return
	}
	p.loaded = true
	if p.Secrets == nil {
		return
	}
	for name, v := range p.Secrets() {
		p.addLocked(v, "[secret:"+name+"]", false)
	}
}

// SetSecrets makes f the printer's Secrets: the values of the one before
// are no longer hidden as [secret:NAME], and f is called on first use.
// It locks by itself, so it is safe while AddValue runs elsewhere.
func (p *Printer) SetSecrets(f func() map[string]string) {
	p.hmu.Lock()
	defer p.hmu.Unlock()
	p.Secrets, p.loaded = f, false
	p.hide = keepOnly(p.hide, func(h *hidden) bool {
		if !h.added {
			return false
		}
		// AddValue hid it too: it stays hidden, under no vault's name
		h.vault, h.label = false, Hidden
		return true
	})
}

// keepOnly is a new list of the entries of hide that keep (which may
// change them) says to keep: a hideList taken before goes on reading the
// old one.
func keepOnly(hide []hidden, keep func(*hidden) bool) []hidden {
	kept := make([]hidden, 0, len(hide))
	for _, h := range hide {
		if keep(&h) {
			kept = append(kept, h)
		}
	}
	return kept
}

// addLocked adds v, as it is and as it often travels, under label: by
// AddValue (added) or from the vault. A value both hid stays hidden until
// both forget it (ForgetAdded, SetSecrets), under the vault's name while
// the vault holds it. p.hmu is held.
func (p *Printer) addLocked(v, label string, added bool) {
	if len(v) < minSecret {
		return
	}
	vault := !added
	var known *hidden
	for _, h := range p.hide {
		if h.raw == v {
			if (added && h.added) || (vault && h.vault) {
				return // known already, in the way it is asked for
			}
			known = &h
			if h.vault {
				label = h.label // the vault named it already: AddValue keeps that name
			}
			added, vault = added || h.added, vault || h.vault
			break
		}
	}
	encs := []string{base64.StdEncoding.EncodeToString([]byte(v)), url.QueryEscape(v)}
	// a new list: a hideList taken before goes on reading the old one
	hide := slices.Clone(p.hide)
	if known != nil {
		// AddValue hid it first and now the vault holds it (it takes the
		// vault's name, and HoldsVaultValue sees it), or the other way
		// round (it survives SetSecrets)
		hide = slices.DeleteFunc(hide, func(o hidden) bool {
			return o.added == known.added && o.vault == known.vault && (o.raw == v || slices.Contains(encs, o.raw))
		})
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	j := strings.TrimSuffix(strings.TrimSpace(b.String()), `"`)
	hide = append(hide, hidden{raw: v, json: strings.TrimPrefix(j, `"`), label: label, added: added, vault: vault})
	// the same value as it often travels: base64 (HTTP basic auth,
	// Kubernetes secrets) and URL-encoded (connection strings)
	for _, enc := range encs {
		if enc != v {
			hide = append(hide, hidden{raw: enc, json: enc, label: label, added: added, vault: vault})
		}
	}
	// longest first, so a secret that contains another is hidden whole
	sort.Slice(hide, func(i, j int) bool { return len(hide[i].raw) > len(hide[j].raw) })
	p.hide = hide
}

// AddValue hides v in this command's output from now on, as [hidden]: a secret
// komando read from somewhere other than its vault (env:, file:, op://,
// bw://, kdbx:, vault:, a cloud secret manager), which the vault's list
// does not have.
func (p *Printer) AddValue(v string) {
	p.load()
	p.hmu.Lock()
	defer p.hmu.Unlock()
	p.addLocked(v, Hidden, true)
}

// hideList is the values to hide, loaded on first use.
func (p *Printer) hideList() []hidden {
	p.load()
	p.hmu.RLock()
	defer p.hmu.RUnlock()
	return p.hide
}

// ForgetAdded drops what AddValue added: a value one command read is not
// hidden in the next one's output (tests run many in one process). The
// CLI calls it before the command counts as running, never while it runs:
// another command's secret added after that must stay hidden.
func (p *Printer) ForgetAdded() {
	p.hmu.Lock()
	defer p.hmu.Unlock()
	p.hide = keepOnly(p.hide, func(h *hidden) bool {
		h.added = false
		return h.vault
	})
}

// HoldsVaultValue reports whether s holds a value from the vault
// (Printer.Secrets), raw, never what only looks like a secret. komando
// refuses such input from an AI agent: masking each exact value would
// otherwise tell it which of its guesses is a secret.
func (p *Printer) HoldsVaultValue(s string) bool {
	if p.NoRedact || len(s) < minSecret {
		return false
	}
	for _, h := range p.hideList() {
		if h.vault && strings.Contains(s, h.raw) {
			return true
		}
	}
	return false
}
