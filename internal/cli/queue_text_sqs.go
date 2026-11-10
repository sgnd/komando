package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/queuex"
)

// The text of the queue commands for Amazon SQS conns. SQS counts are
// approximate, and the text says so.

func sqsInfoText(d *queuex.Info) string {
	return fmt.Sprintf("Amazon SQS, region %s\nendpoint: %s\naccount:  %s\nqueues:   %d\n", d.Region, d.Endpoint, orDash(d.AccountID), d.Queues)
}

func sqsQueuesText(ts []queuex.Topic) string {
	rows := make([][]string, 0, len(ts))
	for _, t := range ts {
		dlq := orDash(t.DeadLetterQueue)
		if t.MaxReceiveCount > 0 {
			dlq += " after " + strconv.Itoa(t.MaxReceiveCount)
		}
		rows = append(rows, []string{t.Name, map[bool]string{true: "fifo", false: "standard"}[t.Fifo], strconv.FormatInt(t.Messages, 10),
			strconv.FormatInt(t.InFlight, 10), strconv.FormatInt(t.Delayed, 10), dlq})
	}
	return layoutTable([]string{"QUEUE", "TYPE", "MESSAGES", "IN FLIGHT", "DELAYED", "DEAD-LETTER QUEUE"}, rows) +
		"(SQS counts are approximate)\n"
}

func sqsQueueText(t *queuex.TopicDetail) string {
	var b strings.Builder
	d := t.SqsQueueDetail
	fmt.Fprintf(&b, "queue: %s (%s)\nurl:   %s\n", t.Name, map[bool]string{true: "fifo", false: "standard"}[d.Fifo], d.URL)
	fmt.Fprintf(&b, "messages: about %d waiting, %d in flight (received, not yet deleted), %d delayed\n", t.Messages, d.InFlight, d.Delayed)
	fmt.Fprintf(&b, "visibility timeout: %s, kept for: %s, delay: %s, receive wait: %s\n", secs(d.VisibilityTimeout), secs(d.RetentionSeconds),
		secs(d.DelaySeconds), secs(d.ReceiveWait))
	fmt.Fprintf(&b, "largest message: %s, encryption: %s", humanBytes(int64(d.MaxMessageSize)), d.Encryption)
	if d.ContentDedup {
		b.WriteString(", deduplication by content")
	}
	b.WriteString("\n")
	if d.DeadLetterQueue != "" {
		fmt.Fprintf(&b, "dead-letter queue: %s, after %s\n", d.DeadLetterQueue, countOf(d.MaxReceiveCount, "receive"))
	}
	if len(d.DeadLetterSources) > 0 {
		fmt.Fprintf(&b, "dead-letter queue of: %s\n", strings.Join(d.DeadLetterSources, ", "))
	}
	if d.CreatedAt != nil {
		fmt.Fprintf(&b, "created: %s\n", d.CreatedAt.Format(time.RFC3339))
	}
	for _, part := range []struct {
		title string
		m     map[string]string
	}{{"tags", d.Tags}, {"other settings", d.Attributes}} {
		if len(part.m) == 0 {
			continue
		}
		b.WriteString("\n" + part.title + ":\n")
		for _, k := range sortedKeys(part.m) {
			fmt.Fprintf(&b, "  %s=%s\n", k, part.m[k])
		}
	}
	return b.String()
}

// secs is a number of seconds as a duration (90 -> 1m30s).
func secs(n int) string { return (time.Duration(n) * time.Second).String() }

func sqsPeekText(p *queuex.PeekResult) string {
	var b strings.Builder
	for _, m := range p.Messages {
		fmt.Fprintf(&b, "# %s, received %s", m.MessageID, countOf(m.ReceiveCount, "time"))
		if m.SentAt != nil {
			b.WriteString(", sent " + m.SentAt.Format(time.RFC3339))
		}
		if m.MessageGroupID != "" {
			b.WriteString(", group " + m.MessageGroupID)
		}
		if len(m.Headers) > 0 {
			hs := make([]string, 0, len(m.Headers))
			for _, k := range sortedKeys(m.Headers) {
				hs = append(hs, k+"="+m.Headers[k])
			}
			b.WriteString(", attributes " + strings.Join(hs, " "))
		}
		if m.Encoding != "" {
			b.WriteString(", " + m.Encoding)
		}
		writeValue(&b, m)
	}
	if len(p.Messages) == 0 {
		b.WriteString("no messages\n")
		return b.String()
	}
	b.WriteString("(received with visibility timeout 0 and not deleted: every message stays, and each one's receive count went up by one")
	if p.DeliveryLimit > 0 {
		fmt.Fprintf(&b, "; after %d receives SQS moves a message to the dead-letter queue", p.DeliveryLimit)
	}
	b.WriteString(")\n")
	if p.More {
		fmt.Fprintf(&b, "(a sample of %s; the queue holds more, and SQS gives them in no set order)\n", countOf(p.Count, "message"))
	}
	return b.String()
}

func sqsSentText(s *queuex.Sent) string {
	group := ""
	if s.MessageGroupID != "" {
		group = ", message group " + s.MessageGroupID
	}
	if s.DryRun {
		return fmt.Sprintf("would send %s to queue %s%s (nothing sent)\n", humanBytes(int64(s.Size)), s.Queue, group)
	}
	return fmt.Sprintf("sent %s to queue %s%s; message ID %s\n", humanBytes(int64(s.Size)), s.Queue, group, *s.MessageID)
}

func sqsCreatedText(c *queuex.Created) string {
	kind := map[bool]string{true: "FIFO", false: "standard"}[c.Fifo]
	if c.DryRun {
		return fmt.Sprintf("would create %s queue %s (the name is free; nothing created)\n", kind, c.Queue)
	}
	return fmt.Sprintf("created %s queue %s\nurl: %s\n", kind, c.Queue, c.URL)
}

func sqsPurgedText(p *queuex.Purged) string {
	if p.DryRun {
		return fmt.Sprintf("would delete about %s from queue %s, and %d in flight; the queue stays\n", count64(p.Messages, "message"), p.Queue, *p.InFlight)
	}
	return fmt.Sprintf("deleting about %s from queue %s, and %d in flight; the queue stays (SQS may take up to 60 seconds to finish)\n",
		count64(p.Messages, "message"), p.Queue, *p.InFlight)
}
