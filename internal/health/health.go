package health

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Result holds the health check result for a single host.
type Result struct {
	HostID    string        `json:"host_id"`
	Hostname  string        `json:"hostname"`
	Port      int           `json:"port"`
	Alive     bool          `json:"alive"`
	Latency   time.Duration `json:"latency_ms"`
	Error     string        `json:"error,omitempty"`
	CheckedAt time.Time     `json:"checked_at"`
}

// CheckHost performs a TCP dial to check if a host is reachable.
func CheckHost(ctx context.Context, hostname string, port int, timeout time.Duration) Result {
	if timeout == 0 {
		timeout = 5 * time.Second
	}

	start := time.Now()
	addr := fmt.Sprintf("%s:%d", hostname, port)

	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	latency := time.Since(start)

	r := Result{
		Hostname:  hostname,
		Port:      port,
		Latency:   latency,
		CheckedAt: time.Now(),
	}

	if err != nil {
		r.Alive = false
		r.Error = err.Error()
		return r
	}
	conn.Close()
	r.Alive = true
	return r
}

// Host is a minimal interface for health checks.
type Host struct {
	ID       string
	Hostname string
	Port     int
}

// CheckAll checks all hosts concurrently, respecting the given concurrency limit.
func CheckAll(ctx context.Context, hosts []Host, timeout time.Duration, concurrency int) []Result {
	if concurrency <= 0 {
		concurrency = 10
	}
	if len(hosts) == 0 {
		return nil
	}
	if concurrency > len(hosts) {
		concurrency = len(hosts)
	}

	results := make([]Result, len(hosts))
	workCh := make(chan int)
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range workCh {
				host := hosts[idx]
				r := CheckHost(ctx, host.Hostname, host.Port, timeout)
				r.HostID = host.ID
				results[idx] = r
			}
		}()
	}

	for i := range hosts {
		workCh <- i
	}
	close(workCh)

	wg.Wait()
	return results
}
