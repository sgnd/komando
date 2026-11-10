package queuex

import "time"

// What `komando queue` shows of NATS JetStream. The engine itself is in
// internal/queuex/nats, which fills these. JSON names differ from the
// other engines' where the meaning differs (a stream's consumer_count,
// num_replicas), since each result holds one engine's part only.

// NatsInfo is what `queue info` shows of a NATS server and its account.
type NatsInfo struct {
	ServerName  string       `json:"server_name,omitempty"`
	ServerID    string       `json:"server_id"`
	ClusterName string       `json:"cluster_name,omitempty"`
	Connected   string       `json:"connected"`   // the server komando talks to (host:port)
	MaxPayload  int64        `json:"max_payload"` // the largest message the server takes, in bytes
	JetStream   bool         `json:"jetstream"`   // whether the account has JetStream (streams)
	Domain      string       `json:"domain,omitempty"`
	Account     *NatsAccount `json:"account,omitempty"`
}

// NatsAccount is the JetStream use and limits of the conn's account.
type NatsAccount struct {
	Streams      int    `json:"streams"`
	Consumers    int    `json:"consumers"`
	Memory       uint64 `json:"memory"`  // bytes kept in memory streams
	Storage      uint64 `json:"storage"` // bytes kept in file streams
	MaxMemory    int64  `json:"max_memory"`
	MaxStorage   int64  `json:"max_storage"`
	MaxStreams   int    `json:"max_streams"`
	MaxConsumers int    `json:"max_consumers"` // -1: no limit, for all four
}

// NatsStream is what `queue ls` shows of a JetStream stream.
type NatsStream struct {
	Subjects      []string `json:"subjects"`
	Bytes         uint64   `json:"bytes"`
	ConsumerCount int      `json:"consumer_count"`
	Storage       string   `json:"storage"`   // file or memory
	Retention     string   `json:"retention"` // limits, interest or workqueue
	NumReplicas   int      `json:"num_replicas"`
	FirstSeq      uint64   `json:"first_seq"`
	LastSeq       uint64   `json:"last_seq"`
	Sealed        bool     `json:"sealed,omitempty"`
}

// NatsStreamDetail is what `queue describe` shows of a stream.
type NatsStreamDetail struct {
	NatsStream
	Description  string         `json:"description,omitempty"`
	Discard      string         `json:"discard"` // old or new: what goes when a limit is reached
	Limits       NatsLimits     `json:"limits"`
	FirstTime    *time.Time     `json:"first_time,omitempty"`
	LastTime     *time.Time     `json:"last_time,omitempty"`
	NumDeleted   int            `json:"num_deleted"` // holes between first_seq and last_seq
	NumSubjects  uint64         `json:"num_subjects"`
	DenyDelete   bool           `json:"deny_delete,omitempty"`
	DenyPurge    bool           `json:"deny_purge,omitempty"`
	Created      time.Time      `json:"created"`
	Cluster      *NatsCluster   `json:"cluster,omitempty"`
	Mirror       string         `json:"mirror,omitempty"`
	Sources      []string       `json:"sources,omitempty"`
	ConsumerInfo []NatsConsumer `json:"consumer_info"`
}

// NatsLimits are a stream's limits; 0 or -1 is "no limit".
type NatsLimits struct {
	MaxMsgs           int64  `json:"max_msgs"`
	MaxBytes          int64  `json:"max_bytes"`
	MaxAge            string `json:"max_age"` // a duration, "0s" for no limit
	MaxMsgSize        int32  `json:"max_msg_size"`
	MaxMsgsPerSubject int64  `json:"max_msgs_per_subject"`
	MaxConsumers      int    `json:"max_consumers"`
	DuplicateWindow   string `json:"duplicate_window,omitempty"`
}

// NatsCluster is where a stream's copies are: the leader and the others.
type NatsCluster struct {
	Name     string        `json:"name,omitempty"`
	Leader   string        `json:"leader,omitempty"`
	Replicas []NatsReplica `json:"replicas,omitempty"`
}

// NatsReplica is one copy of a stream on another server.
type NatsReplica struct {
	Name    string `json:"name"`
	Current bool   `json:"current"` // caught up with the leader
	Offline bool   `json:"offline,omitempty"`
	Lag     uint64 `json:"lag"` // operations behind the leader
}

// NatsConsumer is one consumer of a stream (`describe`, `groups`, `lag`).
// Pending is what it has not been given yet; AckPending what it was given
// and has not acknowledged.
type NatsConsumer struct {
	Stream         string     `json:"stream"`
	Consumer       string     `json:"consumer,omitempty"` // describe: its name (groups and lag say it as "name")
	Durable        bool       `json:"durable"`
	Kind           string     `json:"kind"`       // pull or push
	AckPolicy      string     `json:"ack_policy"` // explicit, all or none
	FilterSubjects []string   `json:"filter_subjects,omitempty"`
	Pending        uint64     `json:"pending"`
	AckPending     int        `json:"ack_pending"`
	Redelivered    int        `json:"redelivered"`
	Waiting        int        `json:"waiting"`       // pull requests waiting for messages
	DeliveredSeq   uint64     `json:"delivered_seq"` // the last stream sequence it was given
	AckFloorSeq    uint64     `json:"ack_floor_seq"` // every message up to here is acknowledged
	LastActive     *time.Time `json:"last_active,omitempty"`
	Paused         bool       `json:"paused,omitempty"`
}

// NatsMsg is where a message `queue peek` read is in its stream.
type NatsMsg struct {
	Subject  string    `json:"subject"`
	Sequence uint64    `json:"sequence"`
	Time     time.Time `json:"time"`
}

// NatsSent is where a published message went.
type NatsSent struct {
	Subject   string  `json:"subject"`
	Stream    string  `json:"stream"`
	Sequence  *uint64 `json:"sequence"` // null on a dry run
	Duplicate bool    `json:"duplicate,omitempty"`
}

// NatsCreated is the stream `queue create` made.
type NatsCreated struct {
	Stream      string     `json:"stream"`
	Subjects    []string   `json:"subjects"`
	Storage     string     `json:"storage"`
	Retention   string     `json:"retention"`
	Discard     string     `json:"discard"`
	NumReplicas int        `json:"num_replicas"`
	Limits      NatsLimits `json:"limits"`
}
