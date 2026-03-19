package analytics

import (
	"testing"
	"time"

	"github.com/managedssh/managedssh/internal/audit"
)

func makeEvents() []audit.Event {
	now := time.Now()
	return []audit.Event{
		{Timestamp: now, Type: "ssh_connection", HostAlias: "web1", Hostname: "1.1.1.1", User: "root", Port: 22, Success: true},
		{Timestamp: now.Add(-1 * time.Hour), Type: "ssh_connection", HostAlias: "web1", Hostname: "1.1.1.1", User: "root", Port: 22, Success: true},
		{Timestamp: now.Add(-2 * time.Hour), Type: "ssh_connection", HostAlias: "db1", Hostname: "2.2.2.2", User: "admin", Port: 5432, Success: false, Error: "timeout"},
		{Timestamp: now.Add(-3 * time.Hour), Type: "ssh_connection", HostAlias: "web1", Hostname: "1.1.1.1", User: "deploy", Port: 22, Success: true},
		{Timestamp: now.Add(-1 * 24 * time.Hour), Type: "ssh_connection", HostAlias: "db1", Hostname: "2.2.2.2", User: "admin", Port: 5432, Success: true},
		{Timestamp: now, Type: "host_added", HostAlias: "newhost", Success: true}, // Non-connection event.
	}
}

func TestComputeBasicStats(t *testing.T) {
	stats := Compute(makeEvents())

	if stats.TotalConnections != 5 {
		t.Fatalf("expected 5 connections, got %d", stats.TotalConnections)
	}
	if stats.SuccessCount != 4 {
		t.Fatalf("expected 4 successes, got %d", stats.SuccessCount)
	}
	if stats.FailureCount != 1 {
		t.Fatalf("expected 1 failure, got %d", stats.FailureCount)
	}
	if stats.SuccessRate != 80.0 {
		t.Fatalf("expected 80%% success rate, got %.1f%%", stats.SuccessRate)
	}
	if stats.AvgSessionDuration != "" {
		t.Fatalf("expected empty average duration when events have no durations, got %q", stats.AvgSessionDuration)
	}
}

func TestComputeUniqueHostsAndUsers(t *testing.T) {
	stats := Compute(makeEvents())

	if stats.UniqueHosts != 2 {
		t.Fatalf("expected 2 unique hosts, got %d", stats.UniqueHosts)
	}
	if stats.UniqueUsers != 3 {
		t.Fatalf("expected 3 unique users, got %d", stats.UniqueUsers)
	}
}

func TestComputeMostConnected(t *testing.T) {
	stats := Compute(makeEvents())

	if len(stats.MostConnected) != 2 {
		t.Fatalf("expected 2 most connected, got %d", len(stats.MostConnected))
	}
	// web1 has 3 connections, should be first.
	if stats.MostConnected[0].Alias != "web1" {
		t.Fatalf("expected web1 first, got %s", stats.MostConnected[0].Alias)
	}
	if stats.MostConnected[0].Connections != 3 {
		t.Fatalf("expected 3 connections for web1, got %d", stats.MostConnected[0].Connections)
	}
}

func TestComputeRecentFailures(t *testing.T) {
	stats := Compute(makeEvents())

	if len(stats.RecentFailures) != 1 {
		t.Fatalf("expected 1 recent failure, got %d", len(stats.RecentFailures))
	}
	if stats.RecentFailures[0].Error != "timeout" {
		t.Fatal("expected timeout error")
	}
}

func TestComputeConnectionsByDay(t *testing.T) {
	stats := Compute(makeEvents())

	if len(stats.ConnectionsByDay) < 1 {
		t.Fatal("expected at least 1 day with connections")
	}
}

func TestComputeEmpty(t *testing.T) {
	stats := Compute(nil)

	if stats.TotalConnections != 0 {
		t.Fatalf("expected 0 connections, got %d", stats.TotalConnections)
	}
	if stats.SuccessRate != 0 {
		t.Fatalf("expected 0%% success rate, got %.1f%%", stats.SuccessRate)
	}
}

func TestComputeNonConnectionEventsIgnored(t *testing.T) {
	events := []audit.Event{
		{Timestamp: time.Now(), Type: "host_added", HostAlias: "test", Success: true},
		{Timestamp: time.Now(), Type: "host_deleted", HostAlias: "test", Success: true},
	}
	stats := Compute(events)

	if stats.TotalConnections != 0 {
		t.Fatalf("expected 0 connections for non-ssh events, got %d", stats.TotalConnections)
	}
}

func TestMostConnectedLimit(t *testing.T) {
	// Create 15 unique hosts.
	now := time.Now()
	var events []audit.Event
	for i := 0; i < 15; i++ {
		events = append(events, audit.Event{
			Timestamp: now,
			Type:      "ssh_connection",
			HostAlias: string(rune('a' + i)),
			Hostname:  string(rune('a' + i)),
			User:      "root",
			Success:   true,
		})
	}
	stats := Compute(events)

	if len(stats.MostConnected) > 10 {
		t.Fatalf("most connected should be limited to 10, got %d", len(stats.MostConnected))
	}
}

func TestComputeAverageDuration(t *testing.T) {
	now := time.Now()
	events := []audit.Event{
		{Timestamp: now, Type: "ssh_connection", Success: true, Duration: "5s"},
		{Timestamp: now, Type: "ssh_connection", Success: true, Duration: "7s"},
		{Timestamp: now, Type: "ssh_connection", Success: false, Duration: "invalid"},
	}
	stats := Compute(events)
	if stats.AvgSessionDuration != "6s" {
		t.Fatalf("expected 6s average duration, got %q", stats.AvgSessionDuration)
	}
}
