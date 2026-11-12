package queuex

import "time"

// What `komando queue` shows of Google Cloud Pub/Sub. The engine itself is
// in internal/queuex/pubsub, which fills these. Pub/Sub keeps messages in
// subscriptions, not in topics, and its API does not count them, so the
// shared messages fields are -1 ("not known") for Pub/Sub. JSON names are
// Pub/Sub's own where another engine uses the same word (topic_count, id,
// api_endpoint), since all engines' parts sit at the same level.

// PubsubInfo is what `queue info` shows of one Google Cloud project.
type PubsubInfo struct {
	Project           string `json:"project"`
	APIEndpoint       string `json:"api_endpoint"` // the server komando talks to (host:port)
	TopicCount        int    `json:"topic_count"`
	SubscriptionCount int    `json:"subscription_count"`
}

// PubsubTopic is what `queue list` shows of a Pub/Sub topic.
type PubsubTopic struct {
	SubscriptionCount int    `json:"subscription_count"`
	MessageRetention  string `json:"message_retention,omitempty"` // how long the topic itself keeps messages (for seek); "": it does not
}

// PubsubDetail is what `queue describe` shows of a topic or a
// subscription; Resource says which. A subscription's own settings are in
// the embedded PubsubSubscription.
type PubsubDetail struct {
	Resource         string               `json:"resource"`  // topic or subscription
	FullName         string               `json:"full_name"` // projects/P/topics/T or projects/P/subscriptions/S
	Labels           map[string]string    `json:"labels,omitempty"`
	MessageRetention string               `json:"message_retention,omitempty"` // topic: how long it keeps messages itself
	KmsKey           string               `json:"kms_key_name,omitempty"`
	Schema           string               `json:"schema,omitempty"`
	AllowedRegions   []string             `json:"allowed_regions,omitempty"`
	SubscriptionInfo []PubsubSubscription `json:"subscription_info,omitempty"` // topic: its subscriptions
	*PubsubSubscription
}

// PubsubSubscription is one subscription: in `describe` (a topic's
// subscriptions, or one subscription) and in `groups`, where each
// subscription is a line. Every subscription gets every message of its
// topic; the programs that pull from one share its messages.
type PubsubSubscription struct {
	Subscription        string `json:"subscription"` // its short name
	Topic               string `json:"topic"`        // the topic it gets messages from; _deleted-topic_ when that is gone
	Delivery            string `json:"delivery"`     // pull, push, bigquery or cloud-storage
	PushEndpoint        string `json:"push_endpoint,omitempty"`
	AckDeadline         int    `json:"ack_deadline_seconds"` // how long a pulled message stays hidden before it is given out again
	BacklogRetention    string `json:"backlog_retention"`    // how long a message nobody acknowledged is kept
	RetainAcked         bool   `json:"retain_acked"`         // acknowledged messages are kept too (for seek)
	Ordering            bool   `json:"ordering"`             // messages with the same ordering key arrive in order
	ExactlyOnce         bool   `json:"exactly_once"`
	Filter              string `json:"filter,omitempty"`
	DeadLetterTopic     string `json:"dead_letter_topic,omitempty"`
	MaxDeliveryAttempts int    `json:"max_delivery_attempts,omitempty"` // deliveries before a message goes to the dead-letter topic
	Detached            bool   `json:"detached,omitempty"`
	SubscriptionState   string `json:"subscription_state,omitempty"` // active, or resource_error when it cannot deliver
}

// PubsubMessage is what peek read about one Pub/Sub message.
type PubsubMessage struct {
	ID              string     `json:"id"`
	PublishTime     *time.Time `json:"publish_time,omitempty"`
	OrderingKey     string     `json:"ordering_key,omitempty"`
	DeliveryAttempt int        `json:"delivery_attempt,omitempty"` // only with a dead-letter topic: deliveries so far, this peek included
}

// PubsubSent is what Pub/Sub said about a message `queue send` published.
type PubsubSent struct {
	ID          *string `json:"id"` // null on a dry run
	OrderingKey string  `json:"ordering_key,omitempty"`
}

// PubsubCreated is the topic or subscription `queue create` made.
type PubsubCreated struct {
	FullName string            `json:"full_name"`
	OfTopic  string            `json:"of_topic,omitempty"` // a subscription: its topic
	Settings map[string]string `json:"settings,omitempty"`
}
