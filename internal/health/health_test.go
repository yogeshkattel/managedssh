package health

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestCheckHostUnreachable(t *testing.T) {
	ctx := context.Background()
	// Use a non-routable address to ensure quick failure.
	r := CheckHost(ctx, "192.0.2.1", 22, 1*time.Second)
	if r.Alive {
		t.Fatal("non-routable address should be unreachable")
	}
	if r.Error == "" {
		t.Fatal("expected error message for unreachable host")
	}
	if r.Hostname != "192.0.2.1" {
		t.Fatalf("expected hostname 192.0.2.1, got %s", r.Hostname)
	}
	if r.Port != 22 {
		t.Fatalf("expected port 22, got %d", r.Port)
	}
	if r.CheckedAt.IsZero() {
		t.Fatal("CheckedAt should be set")
	}
}

func TestCheckHostReachable(t *testing.T) {
	// Start a local TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().(*net.TCPAddr)
	ctx := context.Background()
	r := CheckHost(ctx, "127.0.0.1", addr.Port, 2*time.Second)

	if !r.Alive {
		t.Fatalf("local listener should be reachable: %s", r.Error)
	}
	if r.Latency <= 0 {
		t.Fatal("latency should be positive")
	}
}

func TestCheckHostDefaultTimeout(t *testing.T) {
	ctx := context.Background()
	r := CheckHost(ctx, "192.0.2.1", 22, 0)
	// Should use default 5s timeout. Just verify it doesn't panic.
	if r.Alive {
		t.Fatal("should not be alive")
	}
}

func TestCheckAllConcurrency(t *testing.T) {
	// Start multiple local listeners.
	var listeners []net.Listener
	var hosts []Host
	for i := 0; i < 5; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		listeners = append(listeners, ln)
		addr := ln.Addr().(*net.TCPAddr)
		hosts = append(hosts, Host{
			ID:       "id-" + string(rune('a'+i)),
			Hostname: "127.0.0.1",
			Port:     addr.Port,
		})
	}

	ctx := context.Background()
	results := CheckAll(ctx, hosts, 2*time.Second, 3)

	if len(results) != 5 {
		t.Fatalf("expected 5 results, got %d", len(results))
	}
	for i, r := range results {
		if !r.Alive {
			t.Fatalf("host %d should be alive: %s", i, r.Error)
		}
		if r.HostID == "" {
			t.Fatalf("host %d should have HostID set", i)
		}
	}
}

func TestCheckAllEmpty(t *testing.T) {
	ctx := context.Background()
	results := CheckAll(ctx, nil, 1*time.Second, 5)
	if len(results) != 0 {
		t.Fatalf("expected 0 results, got %d", len(results))
	}
}

func TestCheckAllContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	hosts := []Host{{ID: "x", Hostname: "192.0.2.1", Port: 22}}
	results := CheckAll(ctx, hosts, 5*time.Second, 1)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Alive {
		t.Fatal("cancelled context should not produce alive result")
	}
}
