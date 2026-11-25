package cli

// The questions for the Message queues area. A "topic" is a Kafka topic,
// a RabbitMQ or SQS queue, a NATS stream or a Pub/Sub topic or
// subscription: the help says which, in plain words.

func init() {
	hints := map[string]formHint{"queue": {}}
	for _, p := range queueFormProviders {
		for k, h := range inventoryHints("queue", p.word, "queue", "Queues", p.kind) {
			hints[k] = h
		}
		hints["queue "+p.word+" info"] = queueHints["info"]
		for _, area := range []string{"topic", "message"} {
			hints["queue "+p.word+" "+area] = formHint{}
		}
		for _, k := range []string{"topic list", "topic show", "topic create", "topic delete", "message list", "message create", "message delete"} {
			hints["queue "+p.word+" "+k] = queueHints[k]
		}
		if p.consumers {
			hints["queue "+p.word+" consumer"] = formHint{}
			hints["queue "+p.word+" consumer list"] = queueHints["consumer list"]
			if p.word != "pubsub" {
				hints["queue "+p.word+" consumer show"] = queueHints["consumer show"]
			}
		}
		for k, h := range queueNext(p.word, p.consumers) {
			hints["queue "+p.word+" "+k] = h
		}
	}
	addFormHints(hints)
}

// queueFormProviders are the providers of the table: the word in the path,
// the kind the Add form asks for, and whether the broker has consumers.
var queueFormProviders = []struct {
	word, kind string
	consumers  bool
}{
	{"kafka", "Apache Kafka", true}, {"rabbitmq", "RabbitMQ", false}, {"nats", "NATS JetStream", true},
	{"sqs", "Amazon SQS", false}, {"pubsub", "Google Cloud Pub/Sub", true},
}

var queueConn = formArg{ask: "Which message queue?", pick: "queue",
	help: "A Kafka, RabbitMQ, NATS, SQS or Pub/Sub queue from your list. Add one with komando queue PROVIDER add."}

// queueHints are the questions of the queue commands, by the words after
// the provider.
var queueHints = map[string]formHint{
	"info":          {args: []formArg{queueConn}},
	"consumer list": {args: []formArg{queueConn}},
	"topic list": {args: []formArg{queueConn, {ask: "Only names like? (leave empty for all)", example: "orders-*",
		help: "A pattern: * stands for any letters, so orders-* lists orders-eu, orders-us ..."}},
		flags: []formFlag{{name: "internal", ask: "Kafka only: also list Kafka's own topics (__consumer_offsets ...)?"}}},
	"topic show": {args: []formArg{queueConn, {ask: "Which topic or queue?", example: "orders",
		help: "Shows its settings, message counts and who reads it. Kafka: a topic. RabbitMQ and SQS: a queue. NATS: a stream. Pub/Sub: a topic, or subscriptions/NAME."}}},
	"consumer show": {args: []formArg{queueConn, {ask: "Which consumer group?", example: "billing",
		help: "Kafka: a consumer group, as consumer list shows. NATS: STREAM/CONSUMER, or the consumer's name alone."}}},
	"message list": {args: []formArg{queueConn, {ask: "Which topic or queue to look into?", example: "orders",
		help: "Shows messages without taking them away. Pub/Sub: a subscription. RabbitMQ needs the management port in the conn."}},
		flags: []formFlag{
			{name: "limit", ask: "Show at most how many messages?", help: "A few is enough for a first look.", def: "10"},
			{name: "oldest", ask: "The oldest messages still kept, not the newest?",
				help: "Kafka and NATS only. RabbitMQ always reads from the front; SQS and Pub/Sub give no order."}}},
	"message create": {args: []formArg{queueConn, {ask: "Send to which topic or queue?", example: "orders",
		help: "It has to exist already. NATS: a subject, like orders.new. Pub/Sub: a topic."}},
		flags: []formFlag{
			{name: "value", ask: "What is the message? (leave empty to read it from a file)", example: `{"id": 42, "status": "paid"}`,
				help: "The text of the message, often JSON."},
			{name: "from", ask: "Or read the message from which file on this computer?", example: "./order.json", local: true,
				help: "Only when you left the message empty."},
			{name: "key", ask: "A key for the message?", example: "customer-7",
				help: "Kafka: messages with the same key stay in order. SQS FIFO queues need one (the message group). Empty for none."}}},
	"topic create": {args: []formArg{queueConn, {ask: "What should the new topic or queue be called?", example: "orders",
		help: "Pub/Sub: subscriptions/NAME makes a subscription; then give its topic below as topic=NAME. An SQS name ending in .fifo makes a FIFO queue."}},
		flags: []formFlag{
			{name: "partitions", ask: "Kafka only: how many partitions?", help: "More partitions let more readers work at once. Empty uses the brokers' default.", example: "6"},
			{name: "replicas", ask: "Kafka and NATS: how many copies?", help: "3 keeps the data when a server fails. Empty uses the default.", example: "3"},
			{name: "type", ask: "RabbitMQ only: which queue type?", choices: []string{"classic", "quorum", "stream"},
				help: "quorum keeps copies on several nodes. Empty uses the server's default."},
			{name: "config", ask: "Any settings? (KEY=VALUE)", example: "retention.ms=604800000",
				help: "Kafka retention.ms=..., RabbitMQ x-max-length=..., NATS max_age=7d, SQS VisibilityTimeout=60, Pub/Sub topic=orders. Empty for none."}}},
	"message delete": {args: []formArg{queueConn, {ask: "Empty which topic or queue?", example: "orders-retry",
		help: "Deletes every waiting message and keeps the topic or queue. Pub/Sub: a subscription. Cannot be undone: try it first."}},
		flags: []formFlag{{name: "all", ask: "Delete every waiting message?", help: "Yes is the only way this command runs: it deletes all of them."}}},
	"topic delete": {args: []formArg{queueConn, {ask: "Delete which topics or queues? (several: separate them with spaces)", example: "old-orders",
		help: "Deletes them with their messages. Pub/Sub: subscriptions/NAME for a subscription. Cannot be undone: try it first."}}},
}

// queueNext are the Next: lines of one provider's queue commands.
func queueNext(p string, consumers bool) map[string]formHint {
	c := "queue " + p + " "
	out := map[string]formHint{
		"topic list":     {next: []string{c + "topic show {} TOPIC", c + "message list {} TOPIC"}},
		"topic show":     {next: []string{c + "message list {} TOPIC"}},
		"message list":   {next: []string{c + "topic show {} TOPIC", c + "message create {} TOPIC --value V --dry-run"}},
		"message create": {next: []string{c + "message list {} TOPIC -n 1"}},
		"topic create":   {next: []string{c + "message create {} TOPIC --value V --dry-run", c + "topic show {} TOPIC"}},
		"message delete": {next: []string{c + "topic list {}"}},
		"topic delete":   {next: []string{c + "topic list {}"}},
	}
	if consumers {
		out["topic list"] = formHint{next: append(out["topic list"].next, c+"consumer list {}")}
		if p != "pubsub" {
			out["topic show"] = formHint{next: append(out["topic show"].next, c+"consumer show {} CONSUMER")}
			out["consumer list"] = formHint{next: []string{c + "consumer show {} CONSUMER"}}
		}
	}
	return out
}
