package capability

import "strings"

// queue: message queues. A queue has no raw command, so its areas stay
// whole: topic, message and, where the broker has them,
// consumer groups.

type queueProvider struct {
	provider
	consumers []string // the consumer verbs this broker has
	topic     string   // a topic of the broker, for the examples
}

var queueProviders = []queueProvider{
	{provider: provider{name: "kafka", connect: []Option{credentialOpt}, entry: "prod-kafka", url: "kafka://10.0.0.8:9092"}, consumers: []string{"list", "show"}, topic: "orders"},
	{provider: provider{name: "rabbitmq", connect: []Option{credentialOpt}, entry: "prod-rabbit", url: "amqps://app@10.0.0.9/"}, topic: "emails"},
	{provider: provider{name: "nats", connect: []Option{credentialOpt}, entry: "prod-nats", url: "nats://app@10.0.0.10:4222"}, consumers: []string{"list", "show"}, topic: "ORDERS"},
	{provider: provider{name: "sqs", connect: []Option{credentialOpt}, entry: "prod-sqs", url: "sqs://eu-west-1"}, topic: "orders"},
	{provider: provider{name: "pubsub", connect: []Option{credentialOpt}, entry: "prod-pubsub", url: "pubsub://my-project"}, consumers: []string{"list"}, topic: "orders"},
}

// areaVerb is one verb of an area, with the command of today it was.
type areaVerb struct{ area, verb, today string }

var queueVerbs = []areaVerb{
	{"topic", "list", "queue.list"}, {"topic", "show", "queue.describe"},
	{"topic", "create", "queue.create"}, {"topic", "delete", "queue.rm"},
	{"message", "list", "queue.peek"}, {"message", "create", "queue.send"}, {"message", "delete", "queue.purge"},
}

var consumerToday = map[string]string{"list": "queue.groups", "show": "queue.lag"}

var allOpt = Option{Name: "all", Kind: Bool, Help: "every waiting message; without it nothing is deleted"}

var queueLeaves = queueTable(queueProviders)

func queueTable(ps []queueProvider) []Leaf {
	var out []Leaf
	for _, p := range ps {
		out = append(out, conns("queue", "queue.add").leaves(p.provider)...)
		info := Leaf{Key: Key{Type: "queue", Provider: p.name, Verb: "info"}, Args: oneName, Today: []string{"queue.info"}}
		completeQueue(&info, p)
		out = append(out, info)
		for _, a := range queueVerbs {
			l := areaLeaf("queue", p.name, a.area, a.verb, a.today)
			completeQueue(&l, p)
			out = append(out, l)
		}
		for _, verb := range p.consumers {
			l := areaLeaf("queue", p.name, "consumer", verb, consumerToday[verb])
			completeQueue(&l, p)
			out = append(out, l)
		}
	}
	return out
}

// areaLeaf is one verb of an area inside a target. What it reads is the
// target's data.
func areaLeaf(typ, prov, area, verb, today string) Leaf {
	l := Leaf{Key: Key{Type: typ, Provider: prov, Area: area, Verb: verb}, Args: []Arg{{Name: "NAME"}, {Name: "ITEM", Optional: verb == "list"}}}
	if today != "" {
		l.Today = []string{today}
	}
	switch verb {
	case "list":
		l.Output, l.Synonyms = TargetData, []string{"ls"}
	case "show", "read":
		l.Output = TargetData
	}
	if typ == "queue" && area == "message" && verb == "delete" {
		l.Options = []Option{allOpt}
	}
	return l
}

// The options of today's queue commands. A number the body checks itself
// (--limit 1 or more, --partitions 1 or more) is the body's: the table
// names the option and the default the body has.
var (
	queueLimit      = Option{Name: "limit", Short: "n", Kind: Int, Default: "1000", Help: "the most topics (or queues, or streams) to show, the first by name"}
	queueInternal   = Option{Name: "internal", Kind: Bool, Help: "Kafka: also list its own topics (__consumer_offsets, ...)"}
	peekLimit       = Option{Name: "limit", Short: "n", Kind: Int, Default: "10", Help: "how many messages"}
	peekOldest      = Option{Name: "oldest", Kind: Bool, Help: "the first messages still kept, not the newest"}
	partitionRead   = Option{Name: "partition", Kind: Int, Help: "Kafka: only this partition, numbered from 0 (default: every partition)"}
	partitionSend   = Option{Name: "partition", Kind: Int, Help: "Kafka: send to this partition, numbered from 0 (default: the broker's choice)"}
	peekIdle        = Option{Name: "idle", Kind: Duration, Default: "5s", Help: "Kafka: stop when no message came for this long"}
	sendValue       = Option{Name: "value", Kind: String, Help: "the message"}
	sendFrom        = Option{Name: "from", Kind: String, Help: "read the message from this file ('-' for stdin)"}
	sendKey         = Option{Name: "key", Kind: String, Help: "Kafka: the message key (picks the partition); SQS: the message group of a FIFO queue; Pub/Sub: the ordering key"}
	sendHeader      = Option{Name: "header", Kind: String, Repeat: true, Pairs: true, Help: "a message header KEY=VALUE (repeatable)"}
	createPartition = Option{Name: "partitions", Kind: Int, Help: "Kafka: how many partitions (default: the broker's)"}
	createReplicas  = Option{Name: "replicas", Kind: Int, Help: "copies of each message. Kafka: copies of each partition; NATS: copies of the stream (default: the broker's; NATS: 1)"}
	createType      = Option{Name: "type", Kind: String, Help: "RabbitMQ: the queue type, classic, quorum or stream (default: the server's)"}
	createConfig    = Option{Name: "config", Kind: String, Repeat: true, Pairs: true, Help: "a setting KEY=VALUE, like retention.ms=86400000 (Kafka), x-max-length=1000 (RabbitMQ), max_age=7d (NATS), VisibilityTimeout=60 (SQS) or ackDeadlineSeconds=60 (Pub/Sub) (repeatable)"}
	consumerLimit   = Option{Name: "limit", Short: "n", Kind: Int, Help: "show at most this many groups, consumers or subscriptions (0 = all)"}
)

// completeQueue gives a queue leaf the arguments, options and texts of the
// command of today it keeps.
func completeQueue(l *Leaf, p queueProvider) {
	cmd := "  komando queue " + p.name + " "
	if l.Area != "" {
		cmd += l.Area + " "
	}
	cmd += l.Verb + " " + p.entry
	topic := p.topic
	of := " of a " + queueWhat[p.name] // every Short differs by its provider (S-1.3)
	switch l.Area + "/" + l.Verb {
	case "/info":
		l.Short = "Show the version and size" + of
		l.Example = cmd + "\n" + cmd + " -o json"
	case "topic/list":
		l.Args = []Arg{{Name: "NAME"}, {Name: "PATTERN", Optional: true}}
		l.Options = []Option{queueInternal, queueLimit}
		l.Short = "List the topics" + of + " with their message counts"
		l.Example = cmd + "\n" + cmd + " '" + strings.ToLower(topic[:1]) + "*' -n 50"
	case "topic/show":
		l.Args = []Arg{{Name: "NAME"}, {Name: "TOPIC"}}
		l.Synonyms = []string{"describe"}
		l.Short = "Show one topic" + of + ": messages, settings, readers"
		l.Example = cmd + " " + topic + "\n" + cmd + " " + topic + " -o json"
	case "topic/create":
		l.Args = []Arg{{Name: "NAME"}, {Name: "TOPIC"}}
		l.Options = []Option{createPartition, createReplicas, createType, createConfig}
		l.Short = "Create a topic" + of
		l.Example = cmd + " " + topic + " --dry-run\n" + cmd + " " + topic + " --config retention.ms=604800000"
	case "topic/delete":
		l.Args = []Arg{{Name: "NAME"}, {Name: "TOPIC", Many: true}}
		l.Short = "Delete topics" + of + " with their messages"
		l.Example = cmd + " old-" + topic + " --dry-run\n" + cmd + " old-" + topic + " --allow-dangerous"
	case "message/list":
		l.Args = []Arg{{Name: "NAME"}, {Name: "TOPIC"}}
		l.Options = []Option{peekLimit, peekOldest, partitionRead, peekIdle}
		l.Short = "Read the newest (or oldest) messages" + of + ", removing none"
		l.Example = cmd + " " + topic + "\n" + cmd + " " + topic + " --oldest -n 5"
	case "message/create":
		l.Args = []Arg{{Name: "NAME"}, {Name: "TOPIC"}}
		l.Options = []Option{sendValue, sendFrom, sendKey, sendHeader, partitionSend}
		l.Short = "Publish one message to a topic" + of
		l.Example = cmd + " " + topic + " --value test --dry-run\n" + cmd + " " + topic + " --from ./order.json --header source=support"
	case "message/delete":
		l.Args = []Arg{{Name: "NAME"}, {Name: "TOPIC"}}
		l.Options = []Option{allOpt}
		l.Short = "Empty a topic" + of + " and keep it"
		l.Example = cmd + " " + topic + "-retry --all --dry-run\n" + cmd + " " + topic + "-retry --all --allow-dangerous"
	case "consumer/list":
		l.Args = []Arg{{Name: "NAME"}}
		l.Options = []Option{consumerLimit}
		l.Short = "List the " + queueReaders[p.name] + of
		l.Example = cmd + "\n" + cmd + " -n 20"
	case "consumer/show":
		l.Args = []Arg{{Name: "NAME"}, {Name: "CONSUMER"}}
		l.Short = "Show how far one consumer is behind" + of
		l.Example = cmd + " billing\n" + cmd + " billing -o json"
	}
}

// queueWhat is how a Short names the broker of a provider.
var queueWhat = map[string]string{"kafka": "Kafka cluster", "rabbitmq": "RabbitMQ broker", "nats": "NATS server",
	"sqs": "SQS account", "pubsub": "Pub/Sub project"}

// queueReaders are what a provider's consumer list lists.
var queueReaders = map[string]string{"kafka": "consumer groups", "nats": "consumers", "pubsub": "subscriptions"}
