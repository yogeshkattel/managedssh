package compliance

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/managedssh/managedssh/internal/audit"
)

// Report represents a compliance audit report.
type Report struct {
	GeneratedAt string        `json:"generated_at"`
	Profile     string        `json:"profile"`
	TotalEvents int           `json:"total_events"`
	DateRange   string        `json:"date_range"`
	Events      []audit.Event `json:"events"`
}

// GenerateReport creates a compliance report from audit events.
func GenerateReport(events []audit.Event, profile string) Report {
	r := Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Profile:     profile,
		TotalEvents: len(events),
		Events:      events,
	}

	if len(events) > 0 {
		// Events are newest-first from audit.Recent.
		newest := events[0].Timestamp.Format("2006-01-02")
		oldest := events[len(events)-1].Timestamp.Format("2006-01-02")
		r.DateRange = fmt.Sprintf("%s to %s", oldest, newest)
	}

	return r
}

// WriteJSON writes the report as formatted JSON.
func WriteJSON(w io.Writer, report Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

// WriteCSV writes the events of a report as CSV.
func WriteCSV(w io.Writer, report Report) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	// Header.
	if err := cw.Write([]string{
		"timestamp", "type", "host_alias", "hostname",
		"user", "port", "success", "error", "duration",
	}); err != nil {
		return err
	}

	for _, ev := range report.Events {
		success := "true"
		if !ev.Success {
			success = "false"
		}
		record := []string{
			ev.Timestamp.Format(time.RFC3339),
			ev.Type,
			ev.HostAlias,
			ev.Hostname,
			ev.User,
			fmt.Sprintf("%d", ev.Port),
			success,
			ev.Error,
			ev.Duration,
		}
		if err := cw.Write(record); err != nil {
			return err
		}
	}
	return nil
}
