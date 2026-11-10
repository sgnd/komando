package pubsub

import (
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
)

// What `queue create --config` takes, with Pub/Sub's own names (the case
// does not matter); labels.KEY=VALUE sets a label on either.
var (
	topicSettings = []string{"messageRetentionDuration", "kmsKeyName"}
	subSettings   = []string{"topic", "ackDeadlineSeconds", "messageRetentionDuration", "retainAckedMessages", "enableMessageOrdering",
		"enableExactlyOnceDelivery", "filter", "deadLetterTopic", "maxDeliveryAttempts", "pushEndpoint"}
)

// settings turns --config into the body of the create call. topic is the
// full name of the topic a subscription gets messages from: "" when r is
// a topic to make.
func (p *Pubsub) settings(r ref, cfg map[string]string) (string, map[string]any, error) {
	topic := ""
	for k, v := range cfg {
		if strings.EqualFold(k, "topic") {
			topic = v
		}
	}
	switch {
	case r.kind == "subscription" && topic == "":
		return "", nil, out.Usage("a subscription needs its topic: add --config topic=TOPIC")
	case r.kind == "topic" && topic != "":
		return "", nil, out.Usage("--config topic= makes a subscription: name it subscriptions/%s, or drop topic=", r.name)
	}
	known := topicSettings
	if topic != "" {
		known = subSettings
		full, err := p.topicName(topic)
		if err != nil {
			return "", nil, err
		}
		topic = full
	}
	body := map[string]any{}
	for k, v := range cfg {
		if err := p.setting(body, known, k, v); err != nil {
			return "", nil, err
		}
	}
	if topic != "" {
		body["topic"] = topic
	}
	return topic, body, nil
}

// topicName is the full name of a topic given as NAME or
// projects/P/topics/NAME (a subscription may read another project's topic).
func (p *Pubsub) topicName(s string) (string, error) {
	if parts := strings.Split(s, "/"); len(parts) == 4 && parts[0] == "projects" && parts[2] == "topics" {
		return s, checkName(parts[3])
	}
	r, err := p.parseRef(s)
	if err == nil && r.kind == "subscription" {
		err = out.Usage("topic=%s names a subscription: give a topic", s)
	}
	return p.full("topic", r.name), err
}

// setting puts one --config KEY=VALUE into body, in the shape the REST
// API takes.
func (p *Pubsub) setting(body map[string]any, known []string, k, v string) error {
	if label, ok := strings.CutPrefix(k, "labels."); ok && label != "" {
		labels, _ := body["labels"].(map[string]string)
		if labels == nil {
			labels = map[string]string{}
			body["labels"] = labels
		}
		labels[label] = v
		return nil
	}
	name := ""
	for _, n := range known {
		if strings.EqualFold(k, n) {
			name = n
		}
	}
	var err error
	switch name {
	case "":
		return out.Usage("unknown Pub/Sub setting %q here (known: %s, and labels.KEY)", k, strings.Join(known, ", "))
	case "topic":
	case "messageRetentionDuration":
		body[name], err = seconds(v)
	case "ackDeadlineSeconds", "maxDeliveryAttempts":
		var n int
		if n, err = strconv.Atoi(v); err != nil {
			return out.Usage("%s is a whole number, not %q", name, v)
		}
		if name == "maxDeliveryAttempts" {
			policy(body)["maxDeliveryAttempts"] = n
		} else {
			body[name] = n
		}
	case "retainAckedMessages", "enableMessageOrdering", "enableExactlyOnceDelivery":
		var b bool
		if b, err = strconv.ParseBool(v); err != nil {
			return out.Usage("%s is true or false, not %q", name, v)
		}
		body[name] = b
	case "deadLetterTopic":
		var full string
		if full, err = p.topicName(v); err == nil {
			policy(body)["deadLetterTopic"] = full
		}
	case "pushEndpoint":
		if !strings.HasPrefix(v, "https://") {
			return out.Usage("pushEndpoint is an https:// address")
		}
		body["pushConfig"] = map[string]any{"pushEndpoint": v}
	default:
		body[name] = v
	}
	return err
}

// policy is the dead-letter policy in body, made when it is not there.
func policy(body map[string]any) map[string]any {
	dl, _ := body["deadLetterPolicy"].(map[string]any)
	if dl == nil {
		dl = map[string]any{}
		body["deadLetterPolicy"] = dl
	}
	return dl
}

// seconds turns a duration (7d, 36h, 600s, or Pub/Sub's own "604800s")
// into the "Ns" Pub/Sub takes.
func seconds(v string) (string, error) {
	d, err := time.ParseDuration(v)
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, derr := strconv.Atoi(days)
		d, err = time.Duration(n)*24*time.Hour, derr
	}
	if err != nil || d < time.Second {
		return "", out.Usage("messageRetentionDuration is a duration such as 7d, 36h or 600s, not %q", v)
	}
	return strconv.FormatInt(int64(d/time.Second), 10) + "s", nil
}
