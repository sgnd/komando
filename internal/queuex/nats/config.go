package nats

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/queuex"
)

// streamKeys are the --config keys `queue create` takes for a stream,
// named as in the server's own stream config.
var streamKeys = []string{"subjects", "description", "storage", "retention", "discard", "max_msgs", "max_bytes", "max_age",
	"max_msg_size", "max_msgs_per_subject", "max_consumers", "duplicate_window"}

// streamConfig is the stream `queue create` makes: the subjects (by
// default the stream's name), file storage, limits retention, and the
// --config settings.
func streamConfig(s queuex.TopicSpec) (jetstream.StreamConfig, error) {
	cfg := jetstream.StreamConfig{Name: s.Topic, Subjects: []string{s.Topic}, Storage: jetstream.FileStorage, Retention: jetstream.LimitsPolicy,
		Discard: jetstream.DiscardOld, MaxMsgs: -1, MaxBytes: -1, MaxMsgsPerSubject: -1, MaxConsumers: -1, MaxMsgSize: -1, Replicas: 1}
	if s.Replicas > 0 {
		cfg.Replicas = int(s.Replicas)
	}
	keys := make([]string, 0, len(s.Config))
	for k := range s.Config {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := setting(&cfg, k, s.Config[k]); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

// setting sets one --config key of a stream.
func setting(cfg *jetstream.StreamConfig, key, v string) error {
	var err error
	switch key {
	case "subjects":
		cfg.Subjects = nil
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				cfg.Subjects = append(cfg.Subjects, s)
			}
		}
		if len(cfg.Subjects) == 0 {
			return out.Usage("--config subjects= needs at least one subject, for example subjects=orders.>")
		}
	case "description":
		cfg.Description = v
	case "storage", "retention", "discard":
		return choice(cfg, key, v)
	case "max_msgs":
		cfg.MaxMsgs, err = strconv.ParseInt(v, 10, 64)
	case "max_bytes":
		cfg.MaxBytes, err = strconv.ParseInt(v, 10, 64)
	case "max_msgs_per_subject":
		cfg.MaxMsgsPerSubject, err = strconv.ParseInt(v, 10, 64)
	case "max_msg_size":
		var n int64
		n, err = strconv.ParseInt(v, 10, 32)
		cfg.MaxMsgSize = int32(n)
	case "max_consumers":
		cfg.MaxConsumers, err = strconv.Atoi(v)
	case "max_age":
		cfg.MaxAge, err = duration(v)
	case "duplicate_window":
		cfg.Duplicates, err = duration(v)
	default:
		return out.Usage("unknown stream setting %q (known: %s)", key, strings.Join(streamKeys, ", "))
	}
	if err != nil {
		return out.Usage("--config %s=%s: give a whole number, or a duration such as 24h or 7d for max_age and duplicate_window", key, v)
	}
	return nil
}

// choice sets storage, retention or discard from its word.
func choice(cfg *jetstream.StreamConfig, key, v string) error {
	ok := true
	switch key + "=" + strings.ToLower(v) {
	case "storage=file":
		cfg.Storage = jetstream.FileStorage
	case "storage=memory":
		cfg.Storage = jetstream.MemoryStorage
	case "retention=limits":
		cfg.Retention = jetstream.LimitsPolicy
	case "retention=interest":
		cfg.Retention = jetstream.InterestPolicy
	case "retention=workqueue":
		cfg.Retention = jetstream.WorkQueuePolicy
	case "discard=old":
		cfg.Discard = jetstream.DiscardOld
	case "discard=new":
		cfg.Discard = jetstream.DiscardNew
	default:
		ok = false
	}
	if !ok {
		words := map[string]string{"storage": "file or memory", "retention": "limits, interest or workqueue", "discard": "old or new"}[key]
		return out.Usage("--config %s takes %s, not %q", key, words, v)
	}
	return nil
}

// duration reads 90s, 24h or 7d (days, which Go's durations lack).
func duration(v string) (time.Duration, error) {
	if days, ok := strings.CutSuffix(v, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n < 0 {
			return 0, strconv.ErrSyntax
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(v)
	if err == nil && d < 0 {
		err = strconv.ErrSyntax
	}
	return d, err
}
