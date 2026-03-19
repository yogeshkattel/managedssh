package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Event represents a single audit log entry.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Type      string    `json:"type"`
	HostAlias string    `json:"host_alias,omitempty"`
	Hostname  string    `json:"hostname,omitempty"`
	User      string    `json:"user,omitempty"`
	Port      int       `json:"port,omitempty"`
	Success   bool      `json:"success"`
	Error     string    `json:"error,omitempty"`
	Duration  string    `json:"duration,omitempty"`
}

// Log provides thread-safe audit logging to a JSON-lines file.
type Log struct {
	mu   sync.Mutex
	path string
}

// NewLog creates a new audit log in the given directory.
func NewLog(dir string) (*Log, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &Log{path: filepath.Join(dir, "audit.jsonl")}, nil
}

// Record appends an event to the audit log.
func (l *Log) Record(ev Event) error {
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now()
	}
	data, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	data = append(data, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()

	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// Recent returns the last N events (newest first).
func (l *Log) Recent(n int) ([]Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := os.ReadFile(l.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var all []Event
	dec := json.NewDecoder(strings.NewReader(string(data)))
	for dec.More() {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			continue
		}
		all = append(all, ev)
	}

	// Reverse to newest-first.
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}

	if n > 0 && n < len(all) {
		all = all[:n]
	}
	return all, nil
}
