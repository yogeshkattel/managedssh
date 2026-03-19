package audit

import (
	"os"
	"testing"
	"time"
)

func TestRecordAndRecent(t *testing.T) {
	dir := t.TempDir()
	log, err := NewLog(dir)
	if err != nil {
		t.Fatal(err)
	}

	// Record events.
	for i := 0; i < 5; i++ {
		err := log.Record(Event{
			Timestamp: time.Now(),
			Type:      "ssh_connection",
			HostAlias: "test-host",
			Hostname:  "1.1.1.1",
			User:      "root",
			Port:      22,
			Success:   i%2 == 0,
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// Read back.
	events, err := log.Recent(3)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 {
		t.Fatalf("expected 3 recent events, got %d", len(events))
	}

	// Should be newest first.
	if events[0].Timestamp.Before(events[1].Timestamp) {
		t.Fatal("events should be newest first")
	}
}

func TestRecentAll(t *testing.T) {
	dir := t.TempDir()
	log, _ := NewLog(dir)

	log.Record(Event{Type: "test1", Success: true})
	log.Record(Event{Type: "test2", Success: true})

	events, err := log.Recent(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}
}

func TestRecentEmpty(t *testing.T) {
	dir := t.TempDir()
	log, _ := NewLog(dir)

	events, err := log.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events, got %d", len(events))
	}
}

func TestAutoTimestamp(t *testing.T) {
	dir := t.TempDir()
	log, _ := NewLog(dir)

	log.Record(Event{Type: "auto_ts", Success: true})

	events, _ := log.Recent(1)
	if events[0].Timestamp.IsZero() {
		t.Fatal("timestamp should be auto-set")
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	log, _ := NewLog(dir)
	log.Record(Event{Type: "perm_test", Success: true})

	info, err := os.Stat(log.path)
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("expected 0600 permissions, got %04o", perm)
	}
}

func TestEventFields(t *testing.T) {
	dir := t.TempDir()
	log, _ := NewLog(dir)

	log.Record(Event{
		Type:      "ssh_connection",
		HostAlias: "myhost",
		Hostname:  "10.0.0.1",
		User:      "deploy",
		Port:      2222,
		Success:   false,
		Error:     "connection refused",
		Duration:  "5s",
	})

	events, _ := log.Recent(1)
	e := events[0]
	if e.Type != "ssh_connection" {
		t.Fatal("type mismatch")
	}
	if e.HostAlias != "myhost" {
		t.Fatal("alias mismatch")
	}
	if e.Hostname != "10.0.0.1" {
		t.Fatal("hostname mismatch")
	}
	if e.User != "deploy" {
		t.Fatal("user mismatch")
	}
	if e.Port != 2222 {
		t.Fatal("port mismatch")
	}
	if e.Success {
		t.Fatal("success should be false")
	}
	if e.Error != "connection refused" {
		t.Fatal("error mismatch")
	}
	if e.Duration != "5s" {
		t.Fatal("duration mismatch")
	}
}
