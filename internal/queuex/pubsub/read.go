package pubsub

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/queuex"
)

// apiTopic is a topic as the REST API gives it.
type apiTopic struct {
	Name                     string            `json:"name"`
	Labels                   map[string]string `json:"labels"`
	KmsKeyName               string            `json:"kmsKeyName"`
	MessageRetentionDuration string            `json:"messageRetentionDuration"`
	MessageStoragePolicy     struct {
		AllowedPersistenceRegions []string `json:"allowedPersistenceRegions"`
	} `json:"messageStoragePolicy"`
	SchemaSettings struct {
		Schema string `json:"schema"`
	} `json:"schemaSettings"`
}

// apiSub is a subscription as the REST API gives it.
type apiSub struct {
	Name       string `json:"name"`
	Topic      string `json:"topic"`
	PushConfig struct {
		PushEndpoint string `json:"pushEndpoint"`
	} `json:"pushConfig"`
	BigqueryConfig            *struct{}         `json:"bigqueryConfig"`
	CloudStorageConfig        *struct{}         `json:"cloudStorageConfig"`
	AckDeadlineSeconds        int               `json:"ackDeadlineSeconds"`
	RetainAckedMessages       bool              `json:"retainAckedMessages"`
	MessageRetentionDuration  string            `json:"messageRetentionDuration"`
	Labels                    map[string]string `json:"labels"`
	EnableMessageOrdering     bool              `json:"enableMessageOrdering"`
	EnableExactlyOnceDelivery bool              `json:"enableExactlyOnceDelivery"`
	Filter                    string            `json:"filter"`
	Detached                  bool              `json:"detached"`
	State                     string            `json:"state"`
	DeadLetterPolicy          *struct {
		DeadLetterTopic     string `json:"deadLetterTopic"`
		MaxDeliveryAttempts int    `json:"maxDeliveryAttempts"`
	} `json:"deadLetterPolicy"`
}

type topicsPage struct {
	Topics        []apiTopic `json:"topics"`
	NextPageToken string     `json:"nextPageToken"`
}

type subsPage struct {
	Subscriptions []apiSub `json:"subscriptions"`
	NextPageToken string   `json:"nextPageToken"`
}

// list reads every page of a list call (topics or subscriptions of the
// project); add takes each page and returns its next page token.
func (p *Pubsub) list(ctx context.Context, what string, page func() any, add func(any) string) error {
	token := ""
	for {
		q := url.Values{"pageSize": {"1000"}}
		if token != "" {
			q.Set("pageToken", token)
		}
		res := page()
		if err := p.call(ctx, http.MethodGet, p.project()+"/"+what+"?"+q.Encode(), nil, res); err != nil {
			return opErr(err, what, nil)
		}
		if token = add(res); token == "" {
			return nil
		}
	}
}

func (p *Pubsub) topics(ctx context.Context) ([]apiTopic, error) {
	var all []apiTopic
	err := p.list(ctx, "topics", func() any { return &topicsPage{} }, func(r any) string {
		pg := r.(*topicsPage)
		all = append(all, pg.Topics...)
		return pg.NextPageToken
	})
	return all, err
}

func (p *Pubsub) subscriptions(ctx context.Context) ([]apiSub, error) {
	var all []apiSub
	err := p.list(ctx, "subscriptions", func() any { return &subsPage{} }, func(r any) string {
		pg := r.(*subsPage)
		all = append(all, pg.Subscriptions...)
		return pg.NextPageToken
	})
	return all, err
}

// Info is the project at a glance: where komando talks to, and how many
// topics and subscriptions it has.
func (p *Pubsub) Info(ctx context.Context) (*queuex.Info, error) {
	ts, err := p.topics(ctx)
	if err != nil {
		return nil, err
	}
	ss, err := p.subscriptions(ctx)
	if err != nil {
		return nil, err
	}
	return &queuex.Info{Engine: "pubsub", PubsubInfo: &queuex.PubsubInfo{Project: p.t.Project, APIEndpoint: p.t.Address,
		TopicCount: len(ts), SubscriptionCount: len(ss)}}, nil
}

// Topics lists the topics whose name matches pattern (shell style:
// orders-*), with how many subscriptions each has. Pub/Sub does not count
// messages, so messages is -1.
func (p *Pubsub) Topics(ctx context.Context, pattern string, internal bool) ([]queuex.Topic, error) {
	if internal {
		return nil, queuex.NotSupported("--internal", "pubsub", "Pub/Sub has no topics of its own: drop --internal")
	}
	ts, err := p.topics(ctx)
	if err != nil {
		return nil, err
	}
	ss, err := p.subscriptions(ctx)
	if err != nil {
		return nil, err
	}
	subs := map[string]int{}
	for _, s := range ss {
		subs[s.Topic]++
	}
	res := []queuex.Topic{}
	for _, t := range ts {
		if name := shortName(t.Name); queuex.Match(pattern, name) {
			res = append(res, queuex.Topic{Name: name, Messages: -1,
				PubsubTopic: &queuex.PubsubTopic{SubscriptionCount: subs[t.Name], MessageRetention: duration(t.MessageRetentionDuration)}})
		}
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res, nil
}

// getTopic reads one topic, or TOPIC_NOT_FOUND.
func (p *Pubsub) getTopic(ctx context.Context, name string) (*apiTopic, error) {
	var t apiTopic
	if err := p.call(ctx, http.MethodGet, p.path(ref{name: name}, "topic"), nil, &t); err != nil {
		return nil, opErr(err, name, topicNotFound)
	}
	return &t, nil
}

// getSub reads one subscription, or SUBSCRIPTION_NOT_FOUND.
func (p *Pubsub) getSub(ctx context.Context, name string) (*apiSub, error) {
	var s apiSub
	if err := p.call(ctx, http.MethodGet, p.path(ref{name: name}, "subscription"), nil, &s); err != nil {
		return nil, opErr(err, name, subNotFound)
	}
	return &s, nil
}

// Describe shows a topic (its settings and its subscriptions) or a
// subscription. A bare name is a topic first; when there is no topic of
// that name, a subscription.
func (p *Pubsub) Describe(ctx context.Context, name string) (*queuex.TopicDetail, error) {
	r, err := p.parseRef(name)
	if err != nil {
		return nil, err
	}
	if r.kind != "subscription" {
		t, err := p.getTopic(ctx, r.name)
		switch {
		case err == nil:
			return p.describeTopic(ctx, t)
		case r.kind == "topic" || !isCode(err, "TOPIC_NOT_FOUND"):
			return nil, err
		}
		if s, serr := p.getSub(ctx, r.name); serr == nil {
			return describeSub(s), nil
		}
		return nil, err
	}
	s, err := p.getSub(ctx, r.name)
	if err != nil {
		return nil, err
	}
	return describeSub(s), nil
}

func (p *Pubsub) describeTopic(ctx context.Context, t *apiTopic) (*queuex.TopicDetail, error) {
	d := &queuex.PubsubDetail{Resource: "topic", FullName: t.Name, Labels: t.Labels, MessageRetention: duration(t.MessageRetentionDuration),
		KmsKey: t.KmsKeyName, Schema: t.SchemaSettings.Schema, AllowedRegions: t.MessageStoragePolicy.AllowedPersistenceRegions,
		SubscriptionInfo: []queuex.PubsubSubscription{}}
	ss, err := p.subscriptions(ctx)
	if err != nil {
		return nil, err
	}
	for _, s := range ss {
		if s.Topic == t.Name {
			d.SubscriptionInfo = append(d.SubscriptionInfo, subscriptionOf(&s))
		}
	}
	sort.Slice(d.SubscriptionInfo, func(i, j int) bool { return d.SubscriptionInfo[i].Subscription < d.SubscriptionInfo[j].Subscription })
	return &queuex.TopicDetail{Name: shortName(t.Name), Messages: -1, PubsubDetail: d}, nil
}

func describeSub(s *apiSub) *queuex.TopicDetail {
	sub := subscriptionOf(s)
	d := &queuex.PubsubDetail{Resource: "subscription", FullName: s.Name, Labels: s.Labels, PubsubSubscription: &sub}
	return &queuex.TopicDetail{Name: sub.Subscription, Messages: -1, PubsubDetail: d}
}

// subscriptionOf is what komando shows of a subscription.
func subscriptionOf(s *apiSub) queuex.PubsubSubscription {
	sub := queuex.PubsubSubscription{
		Subscription: shortName(s.Name), Topic: shortName(s.Topic), Delivery: "pull", PushEndpoint: s.PushConfig.PushEndpoint,
		AckDeadline: s.AckDeadlineSeconds, BacklogRetention: duration(s.MessageRetentionDuration), RetainAcked: s.RetainAckedMessages,
		Ordering: s.EnableMessageOrdering, ExactlyOnce: s.EnableExactlyOnceDelivery, Filter: s.Filter, Detached: s.Detached,
		SubscriptionState: strings.ToLower(s.State),
	}
	if s.Topic == "_deleted-topic_" {
		sub.Topic = s.Topic
	}
	switch {
	case s.PushConfig.PushEndpoint != "":
		sub.Delivery = "push"
	case s.BigqueryConfig != nil:
		sub.Delivery = "bigquery"
	case s.CloudStorageConfig != nil:
		sub.Delivery = "cloud-storage"
	}
	if sub.BacklogRetention == "" {
		sub.BacklogRetention = (7 * 24 * time.Hour).String() // Pub/Sub's default
	}
	if dl := s.DeadLetterPolicy; dl != nil && dl.DeadLetterTopic != "" {
		sub.DeadLetterTopic, sub.MaxDeliveryAttempts = shortName(dl.DeadLetterTopic), dl.MaxDeliveryAttempts
		if sub.MaxDeliveryAttempts == 0 {
			sub.MaxDeliveryAttempts = 5 // Pub/Sub's default
		}
	}
	return sub
}

// Groups lists the subscriptions: in Pub/Sub, each subscription gets every
// message of its topic, and the programs that pull from it share them,
// like a Kafka consumer group. Pub/Sub does not say who pulls or how far
// behind they are, so members is 0 and lag -1.
func (p *Pubsub) Groups(ctx context.Context) ([]queuex.Group, error) {
	ss, err := p.subscriptions(ctx)
	if err != nil {
		return nil, err
	}
	res := []queuex.Group{}
	for i := range ss {
		sub := subscriptionOf(&ss[i])
		state := sub.SubscriptionState
		if sub.Detached {
			state = "detached"
		}
		res = append(res, queuex.Group{Name: sub.Subscription, State: state, Protocol: sub.Delivery, Topics: []string{sub.Topic}, Lag: -1, PubsubSubscription: &sub})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res, nil
}

// duration reads a duration as Google writes it ("604800s", "3.5s") and
// gives it the Go way (168h0m0s); "" stays "".
func duration(s string) string {
	f, err := strconv.ParseFloat(strings.TrimSuffix(s, "s"), 64)
	if s == "" || err != nil {
		return s
	}
	return time.Duration(f * float64(time.Second)).String()
}
