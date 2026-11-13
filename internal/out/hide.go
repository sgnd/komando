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

// addLocked adds v, as it is and as it often travels, under label. p.hmu
// is held.
func (p *Printer) addLocked(v, label string, added bool) {
	if len(v) < minSecret {
		return
	}
	for _, h := range p.hide {
		if h.raw == v {
			return // known already, under its own name
		}
	}
	// a new list: a hideList taken before goes on reading the old one
	hide := slices.Clone(p.hide)
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	j := strings.TrimSuffix(strings.TrimSpace(b.String()), `"`)
	hide = append(hide, hidden{raw: v, json: strings.TrimPrefix(j, `"`), label: label, added: added})
	// the same value as it often travels: base64 (HTTP basic auth,
	// Kubernetes secrets) and URL-encoded (connection strings)
	for _, enc := range []string{base64.StdEncoding.EncodeToString([]byte(v)), url.QueryEscape(v)} {
		if enc != v {
			hide = append(hide, hidden{raw: enc, json: enc, label: label, added: added})
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

// forgetAdded drops what AddValue added: a value one command read is not
// hidden in the next one's output (tests run many in one process).
func (p *Printer) forgetAdded() {
	p.hmu.Lock()
	defer p.hmu.Unlock()
	p.hide = slices.DeleteFunc(slices.Clone(p.hide), func(h hidden) bool { return h.added })
}
