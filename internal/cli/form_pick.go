package cli

import (
	"context"
	"slices"
	"strings"

	"github.com/sgnd/komando/internal/store"
)

// formPickOrType is a list that also takes a typed answer: type to filter,
// Enter picks the row under the cursor, or what was typed when no row is
// left (a selector like tag:prod, or several names).
func formPickOrType(ctx context.Context, t *menuTerm, l *menuList, q formQ, st *store.State, a formAnswers, scr menuScreen, cur string) (string, error) {
	l.rows, l.typing = formOptionalRows(q, q.choices(st, a)), true
	l.point(cur)
	l.empty = "Enter takes what you typed"
	scr.footer = "↑↓ move · type to filter or write it · Enter choose · Esc back · Ctrl-C cancel"
	for {
		var v string
		moved := false
		err := menuShow(ctx, t, l, scr, func(k menuKey, page int) (bool, error) {
			if k.kind == keyEnter {
				v = formPicked(l, moved)
				return true, nil
			}
			switch k.kind {
			case keyUp, keyDown, keyHome, keyEnd, keyPageUp, keyPageDown:
				moved = true
			case keyRune, keyBackspace, keyClear:
				moved = false
			}
			switch l.update(k, page) {
			case menuQuit:
				return true, errFormCancel
			case menuBack:
				return true, errMenuBack
			}
			return false, nil
		})
		if err != nil {
			return "", err
		}
		if v == "" && !q.optional {
			l.note, l.warn = "pick one, or type it", true
			continue
		}
		if p := formTypedProblem(st, q, a, l, v); p != "" { // a row needs no check
			l.note, l.warn = p, true
			continue
		}
		return v, nil
	}
}

// formOptionalRows puts "Leave it empty" first on a list a person may skip.
func formOptionalRows(q formQ, rows []menuRow) []menuRow {
	if !q.optional || slices.ContainsFunc(rows, func(r menuRow) bool { return r.value == "" }) {
		return rows
	}
	return append([]menuRow{{label: "Leave it empty", detail: "use the command's usual behaviour", value: ""}}, rows...)
}

// formTypedProblem checks an answer typed into a list: one of the list's
// rows is fine as it is.
func formTypedProblem(st *store.State, q formQ, a formAnswers, l *menuList, v string) string {
	if v == "" || q.check == nil || slices.ContainsFunc(l.rows, func(r menuRow) bool { return r.value == v }) {
		return ""
	}
	return q.check(st, a, v)
}

// formPicked is what Enter gives on a list that also takes typing: the
// row the arrows moved to, a row whose value is exactly what was typed, or
// else the typed text when it reads as a selector or a list (@web, tag:x,
// web*, web1 web2) or matches no row, and the first row it filters to.
func formPicked(l *menuList, moved bool) string {
	typed := strings.TrimSpace(l.filter)
	row, ok := l.chosen()
	switch {
	case typed == "" || moved:
		if ok && len(l.shown()) > 0 {
			return row.value
		}
		return typed
	case slices.ContainsFunc(l.rows, func(r menuRow) bool { return r.value == typed }):
		return typed
	case strings.ContainsAny(typed, "@:*, ") || !ok || len(l.shown()) == 0:
		return typed
	}
	return row.value
}
