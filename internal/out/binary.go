package out

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// A value that is not UTF-8 text reaches the output as base64 (a database's
// binary column as {"base64": ...}, a queue message with "encoding":
// "base64"). The text passes cannot see into base64, so what the bytes
// hold is checked before: a value that holds something this printer hides
// is hidden whole, as a binary file download is refused.

// binaryCheckMax is the most of one value BinaryHidden reads with its
// patterns (they are slow on large values). Past it, a value is hidden
// whole where personal data is hidden from an AI agent; elsewhere only its
// start is read for secret shapes (vault values are looked for in all).
const binaryCheckMax = 256 << 10

// BinaryHidden reports whether raw holds something this printer hides: a
// vault value for anyone and, for an AI agent, a secret by its shape or
// (where personal data is hidden) personal data.
func (p *Printer) BinaryHidden(raw []byte) bool {
	if p.NoRedact || len(raw) == 0 {
		return false
	}
	for _, h := range p.hideList() {
		if bytes.Contains(raw, []byte(h.raw)) {
			return true
		}
	}
	if !p.Mask {
		return false
	}
	if len(raw) > binaryCheckMax {
		if p.Personal {
			return true // too large to read for personal data
		}
		raw = raw[:binaryCheckMax] // the vault values were looked for in all of it
	}
	if p.textHidden(asText(raw, true)) {
		return true
	}
	// text in UTF-16 (Windows): every other byte is 0
	return bytes.Count(raw, []byte{0}) >= len(raw)/3 && p.textHidden(asText(raw, false))
}

// textHidden reports whether the masking passes change text.
func (p *Printer) textHidden(text string) bool {
	return MaskSecrets(text) != text || p.Personal && MaskPersonal(text) != text
}

// asText is the text in raw: the bytes that are none become line breaks
// (split), or are left out.
func asText(raw []byte, split bool) string {
	return strings.Map(func(r rune) rune {
		if r == 0 {
			if split {
				return '\n'
			}
			return -1
		}
		return r
	}, strings.ToValidUTF8(string(raw), "\n"))
}

// hideBase64JSON hides, in a JSON document, the value of every "base64"
// key whose bytes hold something this printer hides (BinaryHidden): it
// becomes {"base64": "[hidden]"}.
func (p *Printer) hideBase64JSON(b []byte) []byte {
	if !bytes.Contains(b, []byte(`"base64"`)) {
		return b
	}
	var outb bytes.Buffer
	lastKey := ""
	i := 0
	for i < len(b) {
		if b[i] != '"' {
			outb.WriteByte(b[i])
			i++
			continue
		}
		end := stringEnd(b, i)
		lit := b[i:end]
		i = end
		j := i
		for j < len(b) && (b[j] == ' ' || b[j] == '\t' || b[j] == '\n' || b[j] == '\r') {
			j++
		}
		var s string
		if json.Unmarshal(lit, &s) != nil {
			outb.Write(lit)
			continue
		}
		if j < len(b) && b[j] == ':' {
			lastKey = s
			outb.Write(lit)
			continue
		}
		key := lastKey
		lastKey = ""
		if key == "base64" && isValueOf(&outb) {
			if raw, err := base64.StdEncoding.DecodeString(s); err == nil && p.BinaryHidden(raw) {
				outb.WriteString(`"` + Hidden + `"`)
				continue
			}
		}
		outb.Write(lit)
	}
	return outb.Bytes()
}

// RedactJSON hides in a JSON document what this printer hides in its JSON
// output, for a caller that shows the document as text too.
func (p *Printer) RedactJSON(b []byte) []byte { return p.redactJSON(b) }

// MaskJSONFields replaces, in a JSON document, the whole value of every
// object key in names (lower case; at any depth) with label. A document
// it cannot read comes back hidden whole.
func MaskJSONFields(b []byte, names map[string]bool, label string) []byte {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var w bytes.Buffer
	if err := maskFields(dec, &w, names, label); err != nil {
		q, _ := json.Marshal(label)
		return q
	}
	return w.Bytes()
}

// maskFields copies the next JSON value from dec to w.
func maskFields(dec *json.Decoder, w *bytes.Buffer, names map[string]bool, label string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case json.Delim:
		w.WriteRune(rune(t))
		for first := true; dec.More(); first = false {
			if !first {
				w.WriteByte(',')
			}
			if t == '{' {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				key, _ := k.(string)
				q, _ := json.Marshal(key)
				w.Write(q)
				w.WriteByte(':')
				if names[strings.ToLower(key)] {
					var skip json.RawMessage
					if err := dec.Decode(&skip); err != nil {
						return err
					}
					if string(skip) == "null" {
						w.WriteString("null") // as SQL keeps NULL
						continue
					}
					q, _ := json.Marshal(label)
					w.Write(q)
					continue
				}
			}
			if err := maskFields(dec, w, names, label); err != nil {
				return err
			}
		}
		end, err := dec.Token() // the closing bracket
		if err != nil {
			return err
		}
		w.WriteRune(rune(end.(json.Delim)))
	case json.Number:
		w.WriteString(t.String())
	default:
		var e bytes.Buffer
		enc := json.NewEncoder(&e)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(t); err != nil {
			return err
		}
		w.Write(bytes.TrimRight(e.Bytes(), "\n"))
	}
	return nil
}
