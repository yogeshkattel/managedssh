package compliance

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/managedssh/managedssh/internal/audit"
)

func sampleEvents() []audit.Event {
	now := time.Now()
	return []audit.Event{
		{Timestamp: now, Type: "ssh_connection", HostAlias: "web1", Hostname: "1.1.1.1", User: "root", Port: 22, Success: true, Duration: "5s"},
		{Timestamp: now.Add(-1 * time.Hour), Type: "ssh_connection", HostAlias: "db1", Hostname: "2.2.2.2", User: "admin", Port: 5432, Success: false, Error: "connection refused"},
	}
}

func TestGenerateReport(t *testing.T) {
	events := sampleEvents()
	report := GenerateReport(events, "default")

	if report.Profile != "default" {
		t.Fatalf("expected profile 'default', got %q", report.Profile)
	}
	if report.TotalEvents != 2 {
		t.Fatalf("expected 2 events, got %d", report.TotalEvents)
	}
	if report.GeneratedAt == "" {
		t.Fatal("GeneratedAt should be set")
	}
	if report.DateRange == "" {
		t.Fatal("DateRange should be set")
	}
	if len(report.Events) != 2 {
		t.Fatalf("expected 2 events in report, got %d", len(report.Events))
	}
}

func TestGenerateReportEmpty(t *testing.T) {
	report := GenerateReport(nil, "test")
	if report.TotalEvents != 0 {
		t.Fatal("expected 0 events")
	}
	if report.DateRange != "" {
		t.Fatal("expected empty date range for no events")
	}
}

func TestWriteJSON(t *testing.T) {
	events := sampleEvents()
	report := GenerateReport(events, "prod")

	var buf bytes.Buffer
	err := WriteJSON(&buf, report)
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's valid JSON.
	var parsed Report
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}
	if parsed.TotalEvents != 2 {
		t.Fatalf("expected 2 events in JSON, got %d", parsed.TotalEvents)
	}
	if parsed.Profile != "prod" {
		t.Fatalf("expected profile 'prod', got %q", parsed.Profile)
	}
}

func TestWriteCSV(t *testing.T) {
	events := sampleEvents()
	report := GenerateReport(events, "default")

	var buf bytes.Buffer
	err := WriteCSV(&buf, report)
	if err != nil {
		t.Fatal(err)
	}

	// Parse the CSV.
	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatalf("invalid CSV output: %v", err)
	}

	// Header + 2 data rows.
	if len(records) != 3 {
		t.Fatalf("expected 3 CSV rows (header + 2 data), got %d", len(records))
	}

	// Verify header.
	header := records[0]
	expectedHeaders := []string{"timestamp", "type", "host_alias", "hostname", "user", "port", "success", "error", "duration"}
	if len(header) != len(expectedHeaders) {
		t.Fatalf("expected %d columns, got %d", len(expectedHeaders), len(header))
	}
	for i, h := range expectedHeaders {
		if header[i] != h {
			t.Fatalf("expected header %q at position %d, got %q", h, i, header[i])
		}
	}

	// Verify first data row.
	if records[1][1] != "ssh_connection" {
		t.Fatalf("expected type ssh_connection, got %q", records[1][1])
	}
	if records[1][6] != "true" {
		t.Fatalf("expected success true, got %q", records[1][6])
	}

	// Verify second data row has error.
	if records[2][7] != "connection refused" {
		t.Fatalf("expected error 'connection refused', got %q", records[2][7])
	}
}

func TestWriteCSVEmpty(t *testing.T) {
	report := GenerateReport(nil, "test")

	var buf bytes.Buffer
	err := WriteCSV(&buf, report)
	if err != nil {
		t.Fatal(err)
	}

	r := csv.NewReader(strings.NewReader(buf.String()))
	records, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	// Just header.
	if len(records) != 1 {
		t.Fatalf("expected 1 CSV row (header only), got %d", len(records))
	}
}
