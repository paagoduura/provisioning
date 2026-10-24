package audit

import (
	"context"
	"sync"
	"time"
)

type Event struct {
	SessionID string
	Type      string
	Result    string
	Reason    string
	At        time.Time
}

type Sink interface {
	Record(context.Context, Event) error
}

type MemorySink struct {
	mu     sync.RWMutex
	events []Event
}

func NewMemorySink() *MemorySink { return &MemorySink{} }
func (s *MemorySink) Record(ctx context.Context, event Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
	return nil
}
func (s *MemorySink) Events() []Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Event, len(s.events))
	copy(out, s.events)
	return out
}
