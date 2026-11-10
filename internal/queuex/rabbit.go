package queuex

// What `komando queue` shows of RabbitMQ. The engine itself is in
// internal/queuex/rabbitmq, which fills these.

// RabbitInfo is what `queue info` shows of a RabbitMQ server.
type RabbitInfo struct {
	Product    string        `json:"product,omitempty"` // RabbitMQ, or the name a compatible server gives
	Cluster    string        `json:"cluster,omitempty"` // the cluster's name
	Vhost      string        `json:"vhost"`
	User       string        `json:"user,omitempty"`
	Platform   string        `json:"platform,omitempty"` // the Erlang version
	Management bool          `json:"management"`         // whether the management API was asked (?management=PORT)
	Nodes      []RabbitNode  `json:"nodes,omitempty"`    // management: the cluster's nodes
	Totals     *RabbitTotals `json:"totals,omitempty"`   // management: counts over the whole cluster
}

// RabbitNode is one node of a RabbitMQ cluster.
type RabbitNode struct {
	Name    string `json:"name"`
	Running bool   `json:"running"`
	Type    string `json:"type,omitempty"` // disc or ram
}

// RabbitTotals are the management API's counts, over every vhost.
type RabbitTotals struct {
	Queues      int   `json:"queues"`
	Exchanges   int   `json:"exchanges"`
	Connections int   `json:"connections"`
	Channels    int   `json:"channels"`
	Consumers   int   `json:"consumers"`
	Messages    int64 `json:"messages"`
	Ready       int64 `json:"ready"`
	Unacked     int64 `json:"unacked"`
}

// RabbitQueue is what `queue ls` shows of a RabbitMQ queue.
type RabbitQueue struct {
	Type      string `json:"type"` // classic, quorum or stream
	Durable   bool   `json:"durable"`
	Ready     int64  `json:"ready"`   // waiting for a consumer
	Unacked   int64  `json:"unacked"` // given to a consumer, not yet acknowledged
	Consumers int    `json:"consumers"`
	State     string `json:"state,omitempty"` // running, idle, flow, down ...
}

// RabbitQueueDetail is what `queue describe` shows of a RabbitMQ queue.
// Without the management API only Ready and Consumers are known.
type RabbitQueueDetail struct {
	Vhost      string           `json:"vhost"`
	Management bool             `json:"management"`
	Ready      int64            `json:"ready"`
	Unacked    *int64           `json:"unacked,omitempty"`
	Consumers  int              `json:"consumers"`
	Type       string           `json:"type,omitempty"`
	Durable    *bool            `json:"durable,omitempty"`
	AutoDelete bool             `json:"auto_delete,omitempty"`
	Exclusive  bool             `json:"exclusive,omitempty"`
	State      string           `json:"state,omitempty"`
	Node       string           `json:"node,omitempty"`
	Policy     string           `json:"policy,omitempty"`
	Arguments  map[string]any   `json:"arguments,omitempty"`
	ConsumerOf []RabbitConsumer `json:"consumer_details,omitempty"`
}

// RabbitConsumer is one consumer of a queue (management API).
type RabbitConsumer struct {
	Tag         string `json:"tag"`
	Connection  string `json:"connection,omitempty"` // the client's address or connection name
	User        string `json:"user,omitempty"`
	AckRequired bool   `json:"ack_required"`
	Prefetch    int    `json:"prefetch"`
	Active      bool   `json:"active"`
}

// RabbitDelivery is a message `queue peek` took from the front of a
// RabbitMQ queue and gave back.
type RabbitDelivery struct {
	Redelivered bool              `json:"redelivered"`          // it had been delivered before this peek
	Deliveries  int64             `json:"deliveries,omitempty"` // quorum queues: times handed out and given back, this peek included
	Exchange    string            `json:"exchange"`             // "" is the default exchange
	RoutingKey  string            `json:"routing_key"`
	Properties  map[string]string `json:"properties,omitempty"` // content_type, message_id, timestamp ...
}

// RabbitCreated is the RabbitMQ queue made.
type RabbitCreated struct {
	Type      string         `json:"type,omitempty"` // "": the vhost's default type
	Durable   bool           `json:"durable"`
	Vhost     string         `json:"vhost"`
	Arguments map[string]any `json:"arguments,omitempty"`
}
