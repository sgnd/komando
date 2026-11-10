package cli

// The questions for the Message queues area. A "topic" is a Kafka topic,
// a RabbitMQ or SQS queue, a NATS stream or a Pub/Sub topic or
// subscription: the help says which, in plain words.

func init() {
	addFormHints(queueHints)
}

var queueConn = formArg{ask: "Which message queue?", pick: "queue",
	help: "A Kafka, RabbitMQ, NATS, SQS or Pub/Sub conn from your list. Add one first with Add, Message queues."}

var queueHints = map[string]formHint{
	"queue info":   {args: []formArg{queueConn}},
	"queue groups": {args: []formArg{queueConn}},
	"queue ls": {args: []formArg{queueConn, {ask: "Only names like? (leave empty for all)", example: "orders-*",
		help: "A pattern: * stands for any letters, so orders-* lists orders-eu, orders-us ..."}},
		flags: []formFlag{{name: "internal", ask: "Kafka only: also list Kafka's own topics (__consumer_offsets ...)?"}}},
	"queue describe": {args: []formArg{queueConn, {ask: "Which topic or queue?", example: "orders",
		help: "Shows its settings, message counts and who reads it. Kafka: a topic. RabbitMQ and SQS: a queue. NATS: a stream. Pub/Sub: a topic, or subscriptions/NAME."}}},
	"queue lag": {args: []formArg{queueConn, {ask: "Which consumer group?", example: "billing",
		help: "Kafka: a consumer group, as queue groups lists. NATS: STREAM/CONSUMER, or the consumer's name alone."}}},
	"queue peek": {args: []formArg{queueConn, {ask: "Which topic or queue to look into?", example: "orders",
		help: "Shows messages without taking them away. Pub/Sub: a subscription. RabbitMQ needs the management port in the conn."}},
		flags: []formFlag{
			{name: "limit", ask: "Show at most how many messages?", help: "A few is enough for a first look.", def: "10"},
			{name: "oldest", ask: "The oldest messages still kept, not the newest?",
				help: "Kafka and NATS only. RabbitMQ always reads from the front; SQS and Pub/Sub give no order."}}},
	"queue send": {args: []formArg{queueConn, {ask: "Send to which topic or queue?", example: "orders",
		help: "It must exist already. NATS: a subject, like orders.new. Pub/Sub: a topic."}},
		flags: []formFlag{
			{name: "value", ask: "What is the message? (leave empty to read it from a file)", example: `{"id": 42, "status": "paid"}`,
				help: "The text of the message, often JSON."},
			{name: "from", ask: "Or read the message from which file on this computer?", example: "./order.json", local: true,
				help: "Only when you left the message empty."},
			{name: "key", ask: "A key for the message?", example: "customer-7",
				help: "Kafka: messages with the same key stay in order. SQS FIFO queues need one (the message group). Empty for none."}}},
	"queue create": {args: []formArg{queueConn, {ask: "What should the new topic or queue be called?", example: "orders",
		help: "Pub/Sub: subscriptions/NAME makes a subscription; then give its topic below as topic=NAME. An SQS name ending in .fifo makes a FIFO queue."}},
		flags: []formFlag{
			{name: "partitions", ask: "Kafka only: how many partitions?", help: "More partitions let more readers work at once. Empty uses the brokers' default.", example: "6"},
			{name: "replicas", ask: "Kafka and NATS: how many copies?", help: "3 keeps the data when a server fails. Empty uses the default.", example: "3"},
			{name: "type", ask: "RabbitMQ only: which queue type?", choices: []string{"classic", "quorum", "stream"},
				help: "quorum keeps copies on several nodes. Empty uses the server's default."},
			{name: "config", ask: "Any settings? (KEY=VALUE)", example: "retention.ms=604800000",
				help: "Kafka retention.ms=..., RabbitMQ x-max-length=..., NATS max_age=7d, SQS VisibilityTimeout=60, Pub/Sub topic=orders. Empty for none."}}},
	"queue purge": {args: []formArg{queueConn, {ask: "Empty which topic or queue?", example: "orders-retry",
		help: "Deletes every waiting message and keeps the topic or queue. Pub/Sub: a subscription. Cannot be undone: try it first."}}},
	"queue rm": {args: []formArg{queueConn, {ask: "Delete which topics or queues? (several: separate them with spaces)", example: "old-orders",
		help: "Deletes them with their messages. Pub/Sub: subscriptions/NAME for a subscription. Cannot be undone: try it first."}}},
}
