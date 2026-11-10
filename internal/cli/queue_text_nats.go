package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/queuex"
)

// The text of the queue commands for NATS JetStream conns.

func natsInfoText(d *queuex.Info) string {
	var b strings.Builder
	name := d.ServerID
	if d.ServerName != "" && d.ServerName != d.ServerID {
		name = d.ServerName + " (" + d.ServerID + ")"
	}
	fmt.Fprintf(&b, "server:  NATS %s, %s\ncluster: %s\naddress: %s\nlargest message: %s\n", orDash(d.Version), name,
		orDash(d.ClusterName), d.Connected, humanBytes(d.MaxPayload))
	if !d.JetStream {
		b.WriteString("\nJetStream: off for this account (no streams; plain NATS keeps no messages)\n")
		return b.String()
	}
	if d.Domain != "" {
		fmt.Fprintf(&b, "domain:  %s\n", d.Domain)
	}
	if a := d.Account; a != nil {
		fmt.Fprintf(&b, "\nJetStream for this account: %s (of %s), %s (of %s)\nstorage: %s on file (of %s), %s in memory (of %s)\n",
			countOf(a.Streams, "stream"), limitOf(int64(a.MaxStreams), false), countOf(a.Consumers, "consumer"), limitOf(int64(a.MaxConsumers), false),
			humanBytes(int64(a.Storage)), limitOf(a.MaxStorage, true), humanBytes(int64(a.Memory)), limitOf(a.MaxMemory, true))
	}
	return b.String()
}

// limitOf is an account limit in words: -1 (or 0) is no limit.
func limitOf(n int64, bytes bool) string {
	switch {
	case n <= 0:
		return "no limit"
	case bytes:
		return humanBytes(n)
	}
	return strconv.FormatInt(n, 10)
}

func natsStreamsText(ts []queuex.Topic) string {
	rows := make([][]string, 0, len(ts))
	for _, t := range ts {
		rows = append(rows, []string{t.Name, strings.Join(t.Subjects, ","), strconv.FormatInt(t.Messages, 10), humanBytes(int64(t.Bytes)),
			strconv.Itoa(t.ConsumerCount), t.Storage, t.Retention, strconv.Itoa(t.NumReplicas)})
	}
	return layoutTable([]string{"STREAM", "SUBJECTS", "MESSAGES", "SIZE", "CONSUMERS", "STORAGE", "RETENTION", "REPLICAS"}, rows)
}

func natsStreamText(t *queuex.TopicDetail) string {
	var b strings.Builder
	d := t.NatsStreamDetail
	fmt.Fprintf(&b, "stream: %s (%s, %s retention, %s)\n", t.Name, d.Storage, d.Retention, countOf(d.NumReplicas, "replica"))
	if d.Description != "" {
		b.WriteString(d.Description + "\n")
	}
	fmt.Fprintf(&b, "subjects: %s\nmessages: %d (%s), sequence %d to %d", strings.Join(d.Subjects, ", "), t.Messages, humanBytes(int64(d.Bytes)), d.FirstSeq, d.LastSeq)
	if d.NumDeleted > 0 {
		fmt.Fprintf(&b, ", %d deleted in between", d.NumDeleted)
	}
	b.WriteString("\n")
	if d.FirstTime != nil {
		fmt.Fprintf(&b, "oldest: %s, newest: %s\n", d.FirstTime.Format(time.RFC3339), d.LastTime.Format(time.RFC3339))
	}
	l := d.Limits
	fmt.Fprintf(&b, "limits: messages %s, size %s, age %s, per subject %s; when full, discard %s\n", limitOf(l.MaxMsgs, false), limitOf(l.MaxBytes, true),
		map[bool]string{true: "no limit", false: l.MaxAge}[l.MaxAge == "0s"], limitOf(l.MaxMsgsPerSubject, false), d.Discard)
	var flags []string
	for name, on := range map[string]bool{"sealed": d.Sealed, "deny-delete": d.DenyDelete, "deny-purge": d.DenyPurge} {
		if on {
			flags = append(flags, name)
		}
	}
	if len(flags) > 0 {
		fmt.Fprintf(&b, "settings: %s\n", strings.Join(sortedStrings(flags), ", "))
	}
	if d.Mirror != "" {
		fmt.Fprintf(&b, "mirror of: %s\n", d.Mirror)
	}
	if len(d.Sources) > 0 {
		fmt.Fprintf(&b, "sources: %s\n", strings.Join(d.Sources, ", "))
	}
	if c := d.Cluster; c != nil {
		fmt.Fprintf(&b, "cluster: %s, leader %s\n", orDash(c.Name), orDash(c.Leader))
		for _, r := range c.Replicas {
			fmt.Fprintf(&b, "  replica %s: %s\n", r.Name, map[bool]string{true: "current", false: fmt.Sprintf("behind by %d", r.Lag)}[r.Current && !r.Offline])
		}
	}
	b.WriteString("\nconsumers:\n")
	if len(d.ConsumerInfo) == 0 {
		b.WriteString("  none\n")
		return b.String()
	}
	b.WriteString(natsConsumerRows(d.ConsumerInfo, func(c queuex.NatsConsumer) string { return c.Consumer }))
	return b.String()
}

func sortedStrings(s []string) []string {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return sortedKeys(m)
}

// natsConsumerRows is a table of consumers; name gives each one's name.
func natsConsumerRows(cs []queuex.NatsConsumer, name func(queuex.NatsConsumer) string) string {
	rows := make([][]string, 0, len(cs))
	for _, c := range cs {
		rows = append(rows, []string{name(c), c.Stream, c.Kind, strconv.FormatUint(c.Pending, 10), strconv.Itoa(c.AckPending),
			strconv.Itoa(c.Redelivered), strconv.Itoa(c.Waiting), orDash(strings.Join(c.FilterSubjects, ","))})
	}
	return layoutTable([]string{"CONSUMER", "STREAM", "KIND", "PENDING", "ACK PENDING", "REDELIVERED", "WAITING", "FILTER"}, rows)
}

func natsGroupsText(gs []queuex.Group) string {
	cs := make([]queuex.NatsConsumer, 0, len(gs))
	for _, g := range gs {
		c := *g.NatsConsumer
		c.Consumer = g.Name
		cs = append(cs, c)
	}
	return natsConsumerRows(cs, func(c queuex.NatsConsumer) string { return c.Consumer }) +
		"(pending: not given to the consumer yet; ack pending: given, not acknowledged yet)\n"
}

func natsLagText(l *queuex.GroupLag) string {
	var b strings.Builder
	durable := map[bool]string{true: "durable", false: "ephemeral"}[l.Durable]
	fmt.Fprintf(&b, "consumer: %s on stream %s (%s %s, ack %s), %s\n", l.Group, l.Stream, durable, l.Kind, l.AckPolicy, l.State)
	fmt.Fprintf(&b, "pending: %d not given to it yet\nack pending: %d given, not acknowledged yet (redelivered: %d)\n", l.Lag, l.AckPending, l.Redelivered)
	fmt.Fprintf(&b, "position: given up to stream sequence %d, all acknowledged up to %d\n", l.DeliveredSeq, l.AckFloorSeq)
	if l.Kind == "pull" {
		fmt.Fprintf(&b, "waiting pull requests: %d\n", l.Waiting)
	}
	if len(l.FilterSubjects) > 0 {
		fmt.Fprintf(&b, "reads subjects: %s\n", strings.Join(l.FilterSubjects, ", "))
	}
	if l.LastActive != nil {
		fmt.Fprintf(&b, "last given a message: %s\n", l.LastActive.Format(time.RFC3339))
	}
	if l.Paused {
		b.WriteString("paused: it gets no messages until it is resumed\n")
	}
	return b.String()
}

func natsPeekText(p *queuex.PeekResult) string {
	var b strings.Builder
	for _, m := range p.Messages {
		fmt.Fprintf(&b, "# sequence %d, %s, subject %s", m.Sequence, m.Time.Format(time.RFC3339), m.Subject)
		for _, k := range sortedKeys(m.Headers) {
			b.WriteString(", " + k + "=" + m.Headers[k])
		}
		if m.Encoding != "" {
			b.WriteString(", " + m.Encoding)
		}
		writeValue(&b, m)
	}
	switch {
	case len(p.Messages) == 0:
		b.WriteString("no messages\n")
	case p.More:
		fmt.Fprintf(&b, "(the %s %s; the stream holds more: raise -n, or use --oldest)\n", p.From, countOf(p.Count, "message"))
	}
	if p.Partial {
		b.WriteString("(the stream has many deleted messages near its end: some of the newest may be missing; use --oldest, or raise -n)\n")
	}
	return b.String()
}

func natsSentText(s *queuex.Sent) string {
	if s.DryRun {
		return fmt.Sprintf("would send %s to %s, kept by stream %s (nothing sent)\n", humanBytes(int64(s.Size)), s.Subject, s.Stream)
	}
	dup := ""
	if s.Duplicate {
		dup = " (a duplicate: the stream had a message with this Nats-Msg-Id already, and kept only that one)"
	}
	return fmt.Sprintf("sent %s to %s; stream %s keeps it as sequence %d%s\n", humanBytes(int64(s.Size)), s.Subject, s.Stream, *s.Sequence, dup)
}

func natsCreatedText(c *queuex.Created) string {
	verb := "created"
	if c.DryRun {
		verb = "would create (the name is free; nothing created):"
	}
	return fmt.Sprintf("%s stream %s for %s (%s storage, %s retention, %s)\n", verb, c.Stream, strings.Join(c.Subjects, ", "), c.Storage, c.Retention,
		countOf(c.NumReplicas, "replica"))
}
