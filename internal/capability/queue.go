package capability

// queue: message queues. A queue has no raw command, so its areas stay
// whole: topic, message and, where the broker has them,
// consumer groups.

type queueProvider struct {
	provider
	consumers []string // the consumer verbs this broker has
}

var queueProviders = []queueProvider{
	{provider: provider{name: "kafka", connect: []Option{credentialOpt}}, consumers: []string{"list", "show"}},
	{provider: provider{name: "rabbitmq", connect: []Option{credentialOpt}}},
	{provider: provider{name: "nats", connect: []Option{credentialOpt}}, consumers: []string{"list", "show"}},
	{provider: provider{name: "sqs", connect: []Option{credentialOpt}}},
	{provider: provider{name: "pubsub", connect: []Option{credentialOpt}}, consumers: []string{"list"}},
}

// areaVerb is one verb of an area, with the command of today it was.
type areaVerb struct{ area, verb, today string }

var queueVerbs = []areaVerb{
	{"topic", "list", "queue.list"}, {"topic", "show", "queue.describe"},
	{"topic", "create", "queue.create"}, {"topic", "delete", "queue.rm"},
	{"message", "list", "queue.peek"}, {"message", "create", "queue.send"}, {"message", "delete", "queue.purge"},
}

var consumerToday = map[string]string{"list": "queue.groups", "show": "queue.lag"}

var allOpt = Option{Name: "all", Kind: Bool, Help: "every waiting message"}

var queueLeaves = queueTable(queueProviders)

func queueTable(ps []queueProvider) []Leaf {
	var out []Leaf
	for _, p := range ps {
		out = append(out, conns("queue", "queue.add").leaves(p.provider)...)
		out = append(out, Leaf{Key: Key{Type: "queue", Provider: p.name, Verb: "info"}, Args: oneName,
			Today: []string{"queue.info"}})
		for _, a := range queueVerbs {
			out = append(out, areaLeaf("queue", p.name, a.area, a.verb, a.today))
		}
		for _, verb := range p.consumers {
			out = append(out, areaLeaf("queue", p.name, "consumer", verb, consumerToday[verb]))
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
