package cli

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/queuex"
)

// The text of the queue commands for Google Cloud Pub/Sub conns. Pub/Sub's
// API does not count messages, and the text says so instead of showing -1.

func pubsubInfoText(d *queuex.Info) string {
	return fmt.Sprintf("Google Cloud Pub/Sub, project %s\nendpoint:      %s\ntopics:        %d\nsubscriptions: %d\n",
		d.Project, d.APIEndpoint, d.TopicCount, d.SubscriptionCount)
}

func pubsubTopicsText(ts []queuex.Topic) string {
	rows := make([][]string, 0, len(ts))
	for _, t := range ts {
		rows = append(rows, []string{t.Name, strconv.Itoa(t.SubscriptionCount), orDash(t.MessageRetention)})
	}
	return layoutTable([]string{"TOPIC", "SUBSCRIPTIONS", "KEEPS MESSAGES"}, rows) +
		"(Pub/Sub does not count messages; `komando queue describe CONN TOPIC` shows a topic's subscriptions)\n"
}

func pubsubDetailText(t *queuex.TopicDetail) string {
	var b strings.Builder
	d := t.PubsubDetail
	fmt.Fprintf(&b, "%s: %s\nname: %s\n", d.Resource, t.Name, d.FullName)
	if d.PubsubSubscription != nil {
		writeSub(&b, *d.PubsubSubscription)
	}
	if d.MessageRetention != "" {
		fmt.Fprintf(&b, "keeps messages for: %s (a subscription can seek back that far)\n", d.MessageRetention)
	}
	if d.KmsKey != "" {
		b.WriteString("encryption key: " + d.KmsKey + "\n")
	}
	if d.Schema != "" {
		b.WriteString("schema: " + d.Schema + "\n")
	}
	if len(d.AllowedRegions) > 0 {
		b.WriteString("kept in: " + strings.Join(d.AllowedRegions, ", ") + "\n")
	}
	if len(d.Labels) > 0 {
		b.WriteString("\nlabels:\n")
		for _, k := range sortedKeys(d.Labels) {
			fmt.Fprintf(&b, "  %s=%s\n", k, d.Labels[k])
		}
	}
	if d.Resource == "topic" {
		b.WriteString("\nsubscriptions (each gets every message):\n")
		if len(d.SubscriptionInfo) == 0 {
			b.WriteString("  none: messages sent now reach nobody\n")
		}
		for _, s := range d.SubscriptionInfo {
			fmt.Fprintf(&b, "  %s (%s, ack deadline %s)%s\n", s.Subscription, s.Delivery, secs(s.AckDeadline), deadLetter(s))
		}
	}
	b.WriteString("(Pub/Sub does not count waiting messages; Cloud Monitoring does)\n")
	return b.String()
}

// writeSub writes one subscription's settings.
func writeSub(b *strings.Builder, s queuex.PubsubSubscription) {
	fmt.Fprintf(b, "topic: %s\ndelivery: %s", s.Topic, s.Delivery)
	if s.PushEndpoint != "" {
		b.WriteString(" to " + s.PushEndpoint)
	}
	fmt.Fprintf(b, "\nack deadline: %s, keeps unacknowledged messages for: %s\n", secs(s.AckDeadline), s.BacklogRetention)
	var flags []string
	for _, f := range []struct {
		on   bool
		what string
	}{{s.Ordering, "ordering by key"}, {s.ExactlyOnce, "exactly-once delivery"}, {s.RetainAcked, "keeps acknowledged messages"}, {s.Detached, "detached from its topic"}} {
		if f.on {
			flags = append(flags, f.what)
		}
	}
	if len(flags) > 0 {
		b.WriteString(strings.Join(flags, ", ") + "\n")
	}
	if s.Filter != "" {
		b.WriteString("filter: " + s.Filter + "\n")
	}
	if s.DeadLetterTopic != "" {
		fmt.Fprintf(b, "dead-letter topic: %s, after %d deliveries\n", s.DeadLetterTopic, s.MaxDeliveryAttempts)
	}
	if s.SubscriptionState != "" && s.SubscriptionState != "active" {
		b.WriteString("state: " + s.SubscriptionState + "\n")
	}
}

func deadLetter(s queuex.PubsubSubscription) string {
	if s.DeadLetterTopic == "" {
		return ""
	}
	return fmt.Sprintf(", dead letters to %s after %d", s.DeadLetterTopic, s.MaxDeliveryAttempts)
}

func pubsubGroupsText(gs []queuex.Group) string {
	rows := make([][]string, 0, len(gs))
	for _, g := range gs {
		rows = append(rows, []string{g.Name, g.Topic, g.Delivery, secs(g.AckDeadline), orDash(g.DeadLetterTopic), orDash(g.State)})
	}
	return layoutTable([]string{"SUBSCRIPTION", "TOPIC", "DELIVERY", "ACK DEADLINE", "DEAD-LETTER TOPIC", "STATE"}, rows) +
		"(Pub/Sub does not say how many messages wait or who pulls them)\n"
}

func pubsubPeekText(p *queuex.PeekResult) string {
	var b strings.Builder
	for _, m := range p.Messages {
		b.WriteString("# " + m.PubsubMessage.ID)
		if m.PublishTime != nil {
			b.WriteString(", published " + m.PublishTime.Format(time.RFC3339))
		}
		if m.OrderingKey != "" {
			b.WriteString(", ordering key " + m.OrderingKey)
		}
		if m.DeliveryAttempt > 0 {
			b.WriteString(", delivery " + strconv.Itoa(m.DeliveryAttempt))
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
		b.WriteString("no messages (or none a pull got at once)\n")
		return b.String()
	}
	b.WriteString("(pulled and given straight back unacknowledged: every message stays and is delivered again")
	if p.DeliveryLimit > 0 {
		fmt.Fprintf(&b, "; each pull counts as a delivery, and after %d Pub/Sub moves a message to the dead-letter topic", p.DeliveryLimit)
	}
	b.WriteString(")\n")
	if p.More {
		fmt.Fprintf(&b, "(the first %s a pull got; there may be more: raise -n)\n", countOf(p.Count, "message"))
	}
	return b.String()
}

func pubsubSentText(s *queuex.Sent) string {
	key := ""
	if s.OrderingKey != "" {
		key = ", ordering key " + s.OrderingKey
	}
	if s.DryRun {
		return fmt.Sprintf("would publish %s to topic %s%s (nothing sent)\n", humanBytes(int64(s.Size)), s.Topic, key)
	}
	return fmt.Sprintf("published %s to topic %s%s; message ID %s\n", humanBytes(int64(s.Size)), s.Topic, key, *s.PubsubSent.ID)
}

func pubsubCreatedText(c *queuex.Created) string {
	what := "topic " + c.Topic
	if c.Subscription != "" {
		what = "subscription " + c.Subscription + " of topic " + c.OfTopic
	}
	if c.DryRun {
		return fmt.Sprintf("would create %s (the name is free; nothing created)\n", what)
	}
	return fmt.Sprintf("created %s\nname: %s\n", what, c.FullName)
}

func pubsubDeletedText(ds []queuex.Deleted, dryRun bool) string {
	var b strings.Builder
	verb := map[bool]string{true: "would delete", false: "deleted"}[dryRun]
	for _, d := range ds {
		what := map[bool]string{true: "subscription", false: "topic"}[d.Subscription != ""]
		switch {
		case !d.Exists:
			fmt.Fprintf(&b, "%s %s does not exist\n", what, d.Name())
		case d.Subscription != "":
			fmt.Fprintf(&b, "%s subscription %s and the messages waiting in it\n", verb, d.Name())
		case d.Consumers != nil && *d.Consumers == 1:
			fmt.Fprintf(&b, "%s topic %s; its subscription stays, with its messages, cut off from the topic\n", verb, d.Name())
		case d.Consumers != nil && *d.Consumers > 1:
			fmt.Fprintf(&b, "%s topic %s; its %d subscriptions stay, with their messages, cut off from the topic\n", verb, d.Name(), *d.Consumers)
		default:
			fmt.Fprintf(&b, "%s topic %s (it has no subscriptions)\n", verb, d.Name())
		}
	}
	return b.String()
}

func pubsubPurgedText(p *queuex.Purged) string {
	if p.DryRun {
		return fmt.Sprintf("would acknowledge every message waiting in subscription %s; the subscription stays (nothing done)\n", p.Subscription)
	}
	return fmt.Sprintf("acknowledged every message published to subscription %s until now (a seek to now); the subscription stays\n", p.Subscription)
}
