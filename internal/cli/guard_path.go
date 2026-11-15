package cli

import (
	"path/filepath"
	"slices"
	"strings"
	"unicode"
)

// foldCase is s as a file system that ignores case compares it (APFS on
// macOS, NTFS on Windows). strings.ToLower is not enough: those systems
// fold ſ (U+017F) to s, and K (U+212A, the Kelvin sign) to k, so ~/.ſsh is
// ~/.ssh there.
func foldCase(s string) string {
	return strings.Map(func(r rune) rune { return unicode.ToLower(unicode.ToUpper(r)) }, s)
}

// kernelPath is the absolute path p, uncleaned, as the system resolves it:
// part by part, each link followed before the next part is read, so a ..
// after a link goes up from where the link leads (proj/l/../x with
// l -> ~/.ssh/sub is ~/.ssh/x), not from proj as filepath.Clean says. The
// parts that do not exist yet are added as they are written.
func kernelPath(p string) string {
	if !filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	vol := filepath.VolumeName(p)
	cur := vol + string(filepath.Separator)
	missing := false
	for _, e := range strings.FieldsFunc(p[len(vol):], func(r rune) bool { return r == '/' || r == filepath.Separator }) {
		switch {
		case e == ".":
			continue
		case e == "..":
			cur = filepath.Dir(cur)
			continue
		}
		next := filepath.Join(cur, e)
		if !missing {
			if r, err := filepath.EvalSymlinks(next); err == nil {
				cur = r
				continue
			}
			missing = true
		}
		cur = next
	}
	return cur
}

// hasDotDot reports whether p has a .. part.
func hasDotDot(p string) bool {
	return slices.Contains(strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == filepath.Separator }), "..")
}

// lexOrKernel is the absolute path raw as the guard reads it: cleaned, as
// it was, unless a .. in it comes after a link, where the system goes
// elsewhere: then the path the system reaches (kernelPath).
func lexOrKernel(raw string) string {
	c := filepath.Clean(raw)
	if !filepath.IsAbs(raw) || !hasDotDot(raw) {
		return c
	}
	if k := kernelPath(raw); k != realPath(c) {
		return k
	}
	return c
}

// underHome is p, a path that starts with the real path of home (home
// with its links followed: /private/var/... for /var/...), written from
// home again, so it compares with the folders the guard names in home.
func underHome(p, home string) string {
	rh := realPath(home)
	if rh == home {
		return p
	}
	if rel, err := filepath.Rel(rh, p); err == nil && filepath.IsLocal(rel) {
		return filepath.Join(home, rel)
	}
	if p == rh {
		return home
	}
	return p
}
