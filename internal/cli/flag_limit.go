package cli

import (
	"reflect"

	"github.com/spf13/cobra"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Every list command has -n/--limit: the most items to show
// (docs/design/ux.md section 3, S-5.8). A command keeps the default it had;
// one that had none starts at 0, no limit. A list that stops at the limit
// sets meta.truncated, and in text mode one stderr line says so.

// limitFlag adds -n/--limit to c with the default def. what says what is
// counted and whether per server or in total.
func limitFlag(c *cobra.Command, n *int, def int, what string) {
	c.Flags().IntVarP(n, "limit", "n", def, "show at most this many "+what+" (0 = all)")
}

// cutRows keeps the first n rows (n <= 0: all) and notes a cut.
func cutRows[T any](rows []T, n int) []T {
	if n <= 0 || len(rows) <= n {
		return rows
	}
	out.P.Cut(n)
	return rows[:n]
}

// cutValue cuts v when it is a slice, as cutRows does; any other value is
// returned as it is. A fleet command's parse returns its rows as any.
func cutValue(v any, n int) any {
	if n <= 0 || v == nil {
		return v
	}
	if l, ok := v.(limiter); ok {
		return l.cutTo(n)
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Slice || rv.Len() <= n {
		return v
	}
	out.P.Cut(n)
	return rv.Slice(0, n).Interface()
}

// limiter is a result that holds its rows inside: cutTo returns it with
// the rows cut to n (cutValue).
type limiter interface{ cutTo(n int) any }

// cutOps wraps a runOps parse so each server's rows stop at n.
func cutOps(n int, parse func(h *store.Host, r *sshx.RunResult) (any, *out.Error)) func(h *store.Host, r *sshx.RunResult) (any, *out.Error) {
	if n <= 0 || parse == nil {
		return parse
	}
	return func(h *store.Host, r *sshx.RunResult) (any, *out.Error) {
		v, err := parse(h, r)
		return cutValue(v, n), err
	}
}

// cutMap keeps the first n keys of m by name (n <= 0: all) and notes a cut.
func cutMap[V any](m map[string]V, n int) map[string]V {
	if n <= 0 || len(m) <= n {
		return m
	}
	keep := map[string]V{}
	for _, k := range cutRows(mapKeys(m), n) {
		keep[k] = m[k]
	}
	return keep
}

// clusterLimitFlag is limitFlag for cluster commands: there -n is
// --namespace, so --limit has no short form.
func clusterLimitFlag(c *cobra.Command, n *int, def int, what string) {
	c.Flags().IntVar(n, "limit", def, "show at most this many "+what+" (0 = all)")
}

// cutLast keeps the last n rows (n <= 0: all), for lists that end with the
// newest, and notes a cut.
func cutLast[T any](rows []T, n int) []T {
	if n <= 0 || len(rows) <= n {
		return rows
	}
	out.P.Cut(n)
	return rows[len(rows)-n:]
}
