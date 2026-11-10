package queuex

import "time"

// What `komando queue` shows of Amazon SQS. The engine itself is in
// internal/queuex/sqs, which fills these. SQS counts are approximate (AWS
// says so itself), and its JSON names are its own where another engine
// uses the same word for something else (created_at, not created).

// SqsInfo is what `queue info` shows of one region of an AWS account.
type SqsInfo struct {
	Region    string `json:"region"`
	Endpoint  string `json:"endpoint"`             // the server komando talks to (host:port)
	AccountID string `json:"account_id,omitempty"` // the account that owns the queues, from their URLs or ?account=
	Queues    int    `json:"queues"`
}

// SqsQueue is what `queue ls` shows of an SQS queue. Messages (in Topic)
// are the ones waiting to be received.
type SqsQueue struct {
	Fifo            bool   `json:"fifo"`
	InFlight        int64  `json:"in_flight"` // received by a consumer, not yet deleted (hidden for their visibility timeout)
	Delayed         int64  `json:"delayed"`   // sent with a delay that has not passed yet
	DeadLetterQueue string `json:"dead_letter_queue,omitempty"`
	MaxReceiveCount int    `json:"max_receive_count,omitempty"` // receives before a message goes to the dead-letter queue
}

// SqsQueueDetail is what `queue describe` shows of an SQS queue.
type SqsQueueDetail struct {
	SqsQueue
	URL               string            `json:"url"`
	ARN               string            `json:"arn"`
	VisibilityTimeout int               `json:"visibility_timeout"` // seconds a received message stays hidden
	RetentionSeconds  int               `json:"retention_seconds"`  // how long SQS keeps a message
	DelaySeconds      int               `json:"delay_seconds"`
	MaxMessageSize    int               `json:"max_message_size"` // bytes
	ReceiveWait       int               `json:"receive_wait"`     // seconds a receive waits for messages (long polling)
	ContentDedup      bool              `json:"content_dedup"`    // fifo: the body's hash is the deduplication ID
	Encryption        string            `json:"encryption"`       // none, sqs-managed or kms:KEY
	CreatedAt         *time.Time        `json:"created_at,omitempty"`
	ModifiedAt        *time.Time        `json:"modified_at,omitempty"`
	DeadLetterSources []string          `json:"dead_letter_sources"` // queues whose dead-letter queue this is
	Tags              map[string]string `json:"tags,omitempty"`
	Attributes        map[string]string `json:"attributes,omitempty"` // the other settings, as SQS names them
}

// SqsMessage is what peek read about one SQS message.
type SqsMessage struct {
	MessageID       string     `json:"message_id"`
	SentAt          *time.Time `json:"sent_at,omitempty"`
	ReceiveCount    int        `json:"receive_count"` // times received, this peek included
	FirstReceivedAt *time.Time `json:"first_received_at,omitempty"`
	MessageGroupID  string     `json:"message_group_id,omitempty"` // fifo
	SequenceNumber  string     `json:"sequence_number,omitempty"`  // fifo
	DeduplicationID string     `json:"deduplication_id,omitempty"` // fifo
}

// SqsSent is what SQS said about a message `queue send` sent.
type SqsSent struct {
	MessageID      *string `json:"message_id"` // null on a dry run
	MessageGroupID string  `json:"message_group_id,omitempty"`
	SequenceNumber string  `json:"sequence_number,omitempty"` // fifo
}

// SqsCreated is the SQS queue `queue create` made.
type SqsCreated struct {
	URL        string            `json:"url,omitempty"` // empty on a dry run
	Fifo       bool              `json:"fifo"`
	Attributes map[string]string `json:"attributes,omitempty"`
}
