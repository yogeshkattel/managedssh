package session

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Recorder captures SSH session I/O to a log file for compliance auditing.
type Recorder struct {
	mu      sync.Mutex
	file    *os.File
	started time.Time
}

// NewRecorder creates a session recorder that writes to the given directory.
// The filename includes the host alias and timestamp.
func NewRecorder(dir, hostAlias, user string) (*Recorder, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	ts := time.Now().UTC().Format("20060102-150405")
	safeName := sanitize(hostAlias)
	safeUser := sanitize(user)
	if safeName == "" {
		safeName = "host"
	}
	if safeUser == "" {
		safeUser = "user"
	}
	filename := fmt.Sprintf("session_%s_%s_%s.log", safeName, safeUser, ts)
	path := filepath.Join(dir, filename)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}

	header := fmt.Sprintf("=== ManagedSSH Session Recording ===\nHost: %s\nUser: %s\nStarted: %s\n====================================\n\n",
		hostAlias, user, time.Now().UTC().Format(time.RFC3339))
	f.WriteString(header)

	return &Recorder{file: f, started: time.Now()}, nil
}

// Write captures output data. Thread-safe.
func (r *Recorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return len(p), nil
	}
	return r.file.Write(p)
}

// Close finalizes the session log with a footer.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	duration := time.Since(r.started).Round(time.Second)
	footer := fmt.Sprintf("\n====================================\nSession ended: %s\nDuration: %s\n====================================\n",
		time.Now().UTC().Format(time.RFC3339), duration)
	r.file.WriteString(footer)
	err := r.file.Close()
	r.file = nil
	return err
}

// WrapWriter returns an io.Writer that writes to both the original writer
// and the recorder (tee pattern).
func (r *Recorder) WrapWriter(w io.Writer) io.Writer {
	return io.MultiWriter(w, r)
}

// ListRecordings returns all session recordings in the given directory.
func ListRecordings(dir string) ([]RecordingInfo, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var recordings []RecordingInfo
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if filepath.Ext(e.Name()) != ".log" {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		recordings = append(recordings, RecordingInfo{
			Name:    e.Name(),
			Size:    info.Size(),
			ModTime: info.ModTime(),
			Path:    filepath.Join(dir, e.Name()),
		})
	}
	return recordings, nil
}

// RecordingInfo holds metadata about a session recording.
type RecordingInfo struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	Path    string    `json:"path"`
}

// sanitize replaces non-alphanumeric characters for safe filenames.
func sanitize(s string) string {
	b := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			b = append(b, c)
		} else {
			b = append(b, '_')
		}
	}
	return string(b)
}
