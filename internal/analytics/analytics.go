package analytics

import (
	"sort"
	"time"

	"github.com/managedssh/managedssh/internal/audit"
)

// Stats holds aggregated connection statistics.
type Stats struct {
	TotalConnections   int            `json:"total_connections"`
	SuccessCount       int            `json:"success_count"`
	FailureCount       int            `json:"failure_count"`
	SuccessRate        float64        `json:"success_rate"`
	UniqueHosts        int            `json:"unique_hosts"`
	UniqueUsers        int            `json:"unique_users"`
	MostConnected      []HostStat     `json:"most_connected"`
	RecentFailures     []audit.Event  `json:"recent_failures"`
	ConnectionsByDay   map[string]int `json:"connections_by_day"`
	AvgSessionDuration string         `json:"avg_session_duration,omitempty"`
}

// HostStat tracks per-host statistics.
type HostStat struct {
	Alias       string `json:"alias"`
	Hostname    string `json:"hostname"`
	Connections int    `json:"connections"`
	Successes   int    `json:"successes"`
	Failures    int    `json:"failures"`
	LastUsed    string `json:"last_used"`
}

// Compute generates analytics from audit events.
func Compute(events []audit.Event) Stats {
	s := Stats{
		ConnectionsByDay: make(map[string]int),
	}

	hostMap := make(map[string]*HostStat)
	userSet := make(map[string]struct{})
	var totalDuration time.Duration
	var durationCount int

	for _, ev := range events {
		if ev.Type != "ssh_connection" {
			continue
		}

		s.TotalConnections++
		if ev.Success {
			s.SuccessCount++
		} else {
			s.FailureCount++
		}

		key := ev.HostAlias + "|" + ev.Hostname
		hs, ok := hostMap[key]
		if !ok {
			hs = &HostStat{
				Alias:    ev.HostAlias,
				Hostname: ev.Hostname,
			}
			hostMap[key] = hs
		}
		hs.Connections++
		if ev.Success {
			hs.Successes++
		} else {
			hs.Failures++
		}
		if ev.Timestamp.Format(time.RFC3339) > hs.LastUsed {
			hs.LastUsed = ev.Timestamp.Format(time.RFC3339)
		}

		if ev.User != "" {
			userSet[ev.User] = struct{}{}
		}

		day := ev.Timestamp.Format("2006-01-02")
		s.ConnectionsByDay[day]++

		if ev.Duration != "" {
			if d, err := time.ParseDuration(ev.Duration); err == nil && d >= 0 {
				totalDuration += d
				durationCount++
			}
		}

		if !ev.Success && len(s.RecentFailures) < 10 {
			s.RecentFailures = append(s.RecentFailures, ev)
		}
	}

	if s.TotalConnections > 0 {
		s.SuccessRate = float64(s.SuccessCount) / float64(s.TotalConnections) * 100
	}
	if durationCount > 0 {
		s.AvgSessionDuration = (totalDuration / time.Duration(durationCount)).Round(time.Second).String()
	}

	s.UniqueHosts = len(hostMap)
	s.UniqueUsers = len(userSet)

	// Build sorted most-connected list.
	for _, hs := range hostMap {
		s.MostConnected = append(s.MostConnected, *hs)
	}
	sort.Slice(s.MostConnected, func(i, j int) bool {
		return s.MostConnected[i].Connections > s.MostConnected[j].Connections
	})
	if len(s.MostConnected) > 10 {
		s.MostConnected = s.MostConnected[:10]
	}

	return s
}
