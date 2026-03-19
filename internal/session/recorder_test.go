package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewRecorder(t *testing.T) {
	dir := t.TempDir()
	sessDir := filepath.Join(dir, "sessions")

	rec, err := NewRecorder(sessDir, "test-host", "root")
	if err != nil {
		t.Fatal(err)
	}
	defer rec.Close()

	if rec.file == nil {
		t.Fatal("file should be open")
	}

	// Verify directory was created.
	info, err := os.Stat(sessDir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() {
		t.Fatal("sessions dir should exist")
	}
}

func TestRecorderWrite(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir, "write-test", "deploy")
	if err != nil {
		t.Fatal(err)
	}

	n, err := rec.Write([]byte("hello world\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 12 {
		t.Fatalf("expected 12 bytes written, got %d", n)
	}

	rec.Close()

	// Read the file and verify content.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}

	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	if !contains(content, "hello world") {
		t.Fatal("recorded content should contain written data")
	}
	if !contains(content, "ManagedSSH Session Recording") {
		t.Fatal("recorded content should contain header")
	}
	if !contains(content, "Session ended") {
		t.Fatal("recorded content should contain footer")
	}
}

func TestRecorderCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir, "close-test", "root")
	if err != nil {
		t.Fatal(err)
	}

	err = rec.Close()
	if err != nil {
		t.Fatal(err)
	}
	// Second close should not error.
	err = rec.Close()
	if err != nil {
		t.Fatal(err)
	}
}

func TestRecorderWriteAfterClose(t *testing.T) {
	dir := t.TempDir()
	rec, _ := NewRecorder(dir, "post-close", "root")
	rec.Close()

	// Write after close should not error (returns len(p)).
	n, err := rec.Write([]byte("should not crash"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 16 {
		t.Fatalf("expected 16, got %d", n)
	}
}

func TestRecorderFilePermissions(t *testing.T) {
	dir := t.TempDir()
	rec, _ := NewRecorder(dir, "perms", "root")
	rec.Write([]byte("data"))
	rec.Close()

	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatal("expected 1 file")
	}
	info, _ := entries[0].Info()
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("expected 0600, got %04o", perm)
	}
}

func TestRecorderWrapWriter(t *testing.T) {
	dir := t.TempDir()
	rec, _ := NewRecorder(dir, "tee", "root")

	var buf [64]byte
	w := rec.WrapWriter(writerFunc(func(p []byte) (int, error) {
		copy(buf[:], p)
		return len(p), nil
	}))

	w.Write([]byte("tee output"))
	rec.Close()

	if string(buf[:10]) != "tee output" {
		t.Fatal("original writer should also receive data")
	}
}

func TestListRecordingsEmpty(t *testing.T) {
	dir := t.TempDir()
	recordings, err := ListRecordings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recordings) != 0 {
		t.Fatalf("expected 0 recordings, got %d", len(recordings))
	}
}

func TestListRecordingsNonexistent(t *testing.T) {
	recordings, err := ListRecordings("/tmp/nonexistent-path-xyz")
	if err != nil {
		t.Fatal(err)
	}
	if recordings != nil {
		t.Fatal("expected nil for nonexistent dir")
	}
}

func TestListRecordings(t *testing.T) {
	dir := t.TempDir()
	rec1, _ := NewRecorder(dir, "host-a", "root")
	rec1.Write([]byte("data1"))
	rec1.Close()

	rec2, _ := NewRecorder(dir, "host-b", "deploy")
	rec2.Write([]byte("data2"))
	rec2.Close()

	recordings, err := ListRecordings(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recordings) != 2 {
		t.Fatalf("expected 2 recordings, got %d", len(recordings))
	}
	for _, r := range recordings {
		if r.Size == 0 {
			t.Fatal("recording size should be > 0")
		}
		if r.Path == "" {
			t.Fatal("recording path should be set")
		}
	}
}

func TestSanitize(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with spaces", "with_spaces"},
		{"a/b/c", "a_b_c"},
		{"prod-web_01", "prod-web_01"},
		{"special@chars!", "special_chars_"},
	}
	for _, tt := range tests {
		got := sanitize(tt.input)
		if got != tt.expected {
			t.Fatalf("sanitize(%q) = %q, want %q", tt.input, got, tt.expected)
		}
	}
}

func TestNewRecorderSanitizesUserInFilename(t *testing.T) {
	dir := t.TempDir()
	rec, err := NewRecorder(dir, "prod/web", "../root")
	if err != nil {
		t.Fatal(err)
	}
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}
	if !strings.HasPrefix(entries[0].Name(), "session_prod_web____root_") {
		t.Fatalf("expected sanitized filename prefix, got %q", entries[0].Name())
	}
}

// writerFunc adapts a function to io.Writer.
type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) {
	return f(p)
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
