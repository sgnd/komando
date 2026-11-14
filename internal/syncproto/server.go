package syncproto

import (
	"errors"
	"maps"
	"slices"
	"sync"
)

// Server is the sync service as a device sees it: append-only logs and
// named blobs, all opaque. The devices trust none of it (SS 4): every
// answer is checked. by and from name the asking device, as the real
// service would know it from the signed request; a hostile server uses it
// to show different devices different things.
type Server interface {
	// AppendAt appends item to log only if the log has exactly at items,
	// so two devices that add a list entry at once cannot both win.
	AppendAt(from DeviceID, log string, at int, item []byte) error
	Append(from DeviceID, log string, item []byte) error
	Read(by DeviceID, log string) ([][]byte, error)
	Put(from DeviceID, name string, data []byte) error
	// Get returns nil, nil for a name that is not there.
	Get(by DeviceID, name string) ([]byte, error)
}

// errConflict is what AppendAt returns when the log moved on.
var errConflict = errors.New("syncproto: log is longer than expected")

// MemServer is an honest in-memory server.
type MemServer struct {
	mu    sync.Mutex
	logs  map[string][][]byte
	blobs map[string][]byte
}

// NewMemServer makes an empty server.
func NewMemServer() *MemServer {
	return &MemServer{logs: map[string][][]byte{}, blobs: map[string][]byte{}}
}

func clone(b []byte) []byte { return append([]byte{}, b...) }

// AppendAt implements Server.
func (s *MemServer) AppendAt(_ DeviceID, log string, at int, item []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.logs[log]) != at {
		return errConflict
	}
	s.logs[log] = append(s.logs[log], clone(item))
	return nil
}

// Append implements Server.
func (s *MemServer) Append(_ DeviceID, log string, item []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs[log] = append(s.logs[log], clone(item))
	return nil
}

// Read implements Server.
func (s *MemServer) Read(_ DeviceID, log string) ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([][]byte, len(s.logs[log]))
	for i, it := range s.logs[log] {
		out[i] = clone(it)
	}
	return out, nil
}

// Put implements Server.
func (s *MemServer) Put(_ DeviceID, name string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.blobs[name] = clone(data)
	return nil
}

// Get implements Server.
func (s *MemServer) Get(_ DeviceID, name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if b, ok := s.blobs[name]; ok {
		return clone(b), nil
	}
	return nil, nil
}

// Snapshot copies everything the server holds (for rollback attacks).
func (s *MemServer) Snapshot() *MemServer {
	s.mu.Lock()
	defer s.mu.Unlock()
	c := NewMemServer()
	for k, v := range s.logs {
		for _, it := range v {
			c.logs[k] = append(c.logs[k], clone(it))
		}
	}
	for k, v := range s.blobs {
		c.blobs[k] = clone(v)
	}
	return c
}

// Restore replaces everything with a snapshot.
func (s *MemServer) Restore(c *MemServer) {
	c = c.Snapshot()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs, s.blobs = c.logs, c.blobs
}

// SetLog replaces a log (for attacks).
func (s *MemServer) SetLog(log string, items [][]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.logs[log] = items
}

// Names lists every log and blob name.
func (s *MemServer) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := slices.Collect(maps.Keys(s.logs))
	names = append(names, slices.Collect(maps.Keys(s.blobs))...)
	slices.Sort(names)
	return names
}

// AllBytes is everything the server holds, names included: what a thief
// of its database gets.
func (s *MemServer) AllBytes() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out [][]byte
	for k, v := range s.logs {
		out = append(out, []byte(k))
		out = append(out, v...)
	}
	for k, v := range s.blobs {
		out = append(out, []byte(k), v)
	}
	return out
}

// Hostile is a server that lies. Each read hook sees what the honest
// server would answer and returns what the device gets instead: it can
// drop, reorder, replay, roll back, fork per device and substitute. Each
// write hook sees what a device stores and returns false to drop it while
// telling the device it was stored (a delete that never happens, an
// append to a fork the hook keeps itself).
type Hostile struct {
	*MemServer
	OnRead     func(by DeviceID, log string, items [][]byte) [][]byte
	OnGet      func(by DeviceID, name string, data []byte) []byte
	OnPut      func(from DeviceID, name string, data []byte) bool
	OnAppendAt func(from DeviceID, log string, at int, item []byte) bool
}

// NewHostile wraps a fresh store.
func NewHostile() *Hostile { return &Hostile{MemServer: NewMemServer()} }

// Read implements Server, through OnRead.
func (h *Hostile) Read(by DeviceID, log string) ([][]byte, error) {
	items, err := h.MemServer.Read(by, log)
	if err != nil || h.OnRead == nil {
		return items, err
	}
	return h.OnRead(by, log, items), nil
}

// Get implements Server, through OnGet.
func (h *Hostile) Get(by DeviceID, name string) ([]byte, error) {
	b, err := h.MemServer.Get(by, name)
	if err != nil || h.OnGet == nil {
		return b, err
	}
	return h.OnGet(by, name, b), nil
}

// Put implements Server, through OnPut.
func (h *Hostile) Put(from DeviceID, name string, data []byte) error {
	if h.OnPut != nil && !h.OnPut(from, name, data) {
		return nil
	}
	return h.MemServer.Put(from, name, data)
}

// AppendAt implements Server, through OnAppendAt.
func (h *Hostile) AppendAt(from DeviceID, log string, at int, item []byte) error {
	if h.OnAppendAt != nil && !h.OnAppendAt(from, log, at, item) {
		return nil
	}
	return h.MemServer.AppendAt(from, log, at, item)
}
