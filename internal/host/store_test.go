package host

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewStoreEmpty(t *testing.T) {
	s := newTestStore(t)
	if len(s.Hosts) != 0 {
		t.Fatalf("expected 0 hosts, got %d", len(s.Hosts))
	}
}

func TestAddAndFilter(t *testing.T) {
	s := newTestStore(t)

	err := s.Add(Host{
		Alias:    "prod-web",
		Hostname: "192.168.1.10",
		Users:    []string{"root"},
		Port:     22,
		AuthType: "key",
		Group:    "production",
		Tags:     []string{"web", "critical"},
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(s.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d", len(s.Hosts))
	}

	h := s.Hosts[0]
	if h.ID == "" {
		t.Fatal("expected auto-generated ID")
	}
	if h.Alias != "prod-web" {
		t.Fatalf("expected alias prod-web, got %s", h.Alias)
	}
	if h.CreatedAt == "" {
		t.Fatal("expected CreatedAt to be set")
	}

	// Filter by alias.
	filtered := s.Filter("prod")
	if len(filtered) != 1 {
		t.Fatalf("expected 1 filtered host, got %d", len(filtered))
	}

	// Filter by group.
	filtered = s.Filter("production")
	if len(filtered) != 1 {
		t.Fatalf("expected 1 host in production group, got %d", len(filtered))
	}

	// Filter by tag.
	filtered = s.Filter("critical")
	if len(filtered) != 1 {
		t.Fatalf("expected 1 host with critical tag, got %d", len(filtered))
	}

	// No match.
	filtered = s.Filter("nonexistent")
	if len(filtered) != 0 {
		t.Fatalf("expected 0 filtered hosts, got %d", len(filtered))
	}
}

func TestUpdate(t *testing.T) {
	s := newTestStore(t)
	s.Add(Host{Alias: "test", Hostname: "1.2.3.4", Users: []string{"admin"}})

	id := s.Hosts[0].ID
	err := s.Update(id, Host{Alias: "updated", Hostname: "5.6.7.8", Users: []string{"user"}})
	if err != nil {
		t.Fatal(err)
	}

	if s.Hosts[0].Alias != "updated" {
		t.Fatalf("expected alias 'updated', got %q", s.Hosts[0].Alias)
	}
	if s.Hosts[0].ID != id {
		t.Fatal("update should preserve ID")
	}
}

func TestUpdateMissingHost(t *testing.T) {
	s := newTestStore(t)
	err := s.Update("missing", Host{Alias: "updated", Hostname: "5.6.7.8", Users: []string{"user"}})
	if !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("expected ErrHostNotFound, got %v", err)
	}
}

func TestDelete(t *testing.T) {
	s := newTestStore(t)
	s.Add(Host{Alias: "a", Hostname: "1.1.1.1", Users: []string{"root"}})
	s.Add(Host{Alias: "b", Hostname: "2.2.2.2", Users: []string{"root"}})

	if len(s.Hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(s.Hosts))
	}

	id := s.Hosts[0].ID
	err := s.Delete(id)
	if err != nil {
		t.Fatal(err)
	}

	if len(s.Hosts) != 1 {
		t.Fatalf("expected 1 host after delete, got %d", len(s.Hosts))
	}
	if s.Hosts[0].Alias != "b" {
		t.Fatal("deleted wrong host")
	}
}

func TestDeleteMissingHost(t *testing.T) {
	s := newTestStore(t)
	err := s.Delete("missing")
	if !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("expected ErrHostNotFound, got %v", err)
	}
}

func TestPersistence(t *testing.T) {
	dir := t.TempDir()
	s1, _ := NewStore(dir)
	s1.Add(Host{Alias: "persist", Hostname: "10.0.0.1", Users: []string{"test"}})

	// Re-read from disk.
	s2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(s2.Hosts) != 1 {
		t.Fatalf("expected 1 host after reload, got %d", len(s2.Hosts))
	}
	if s2.Hosts[0].Alias != "persist" {
		t.Fatal("persisted data mismatch")
	}
}

func TestAtomicWrite(t *testing.T) {
	s := newTestStore(t)
	s.Add(Host{Alias: "atomic", Hostname: "1.1.1.1", Users: []string{"root"}})

	// Verify no .tmp file exists.
	tmpPath := s.path + ".tmp"
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Fatal("tmp file should not exist after successful save")
	}
}

func TestDefaultPort(t *testing.T) {
	s := newTestStore(t)
	s.Add(Host{Alias: "noport", Hostname: "1.1.1.1", Users: []string{"root"}})
	if s.Hosts[0].Port != 22 {
		t.Fatalf("expected default port 22, got %d", s.Hosts[0].Port)
	}
}

func TestNormalize(t *testing.T) {
	h := Host{User: "admin", Users: nil}
	h.Normalize()
	if len(h.Users) != 1 || h.Users[0] != "admin" {
		t.Fatal("Normalize should populate Users from User")
	}
	if h.User != "admin" {
		t.Fatal("Normalize should set User to first of Users")
	}
}

func TestNormalizeDedup(t *testing.T) {
	h := Host{Users: []string{"root", "root", "admin", "root"}}
	h.Normalize()
	if len(h.Users) != 2 {
		t.Fatalf("expected 2 unique users, got %d", len(h.Users))
	}
}

func TestNormalizeTrim(t *testing.T) {
	h := Host{Users: []string{"  root  ", "", "  admin  "}}
	h.Normalize()
	if len(h.Users) != 2 {
		t.Fatalf("expected 2 users, got %d: %v", len(h.Users), h.Users)
	}
	if h.Users[0] != "root" || h.Users[1] != "admin" {
		t.Fatalf("expected trimmed users, got %v", h.Users)
	}
}

func TestGroups(t *testing.T) {
	s := newTestStore(t)
	s.Add(Host{Alias: "a", Hostname: "1.1.1.1", Users: []string{"r"}, Group: "prod"})
	s.Add(Host{Alias: "b", Hostname: "2.2.2.2", Users: []string{"r"}, Group: "staging"})
	s.Add(Host{Alias: "c", Hostname: "3.3.3.3", Users: []string{"r"}, Group: "prod"})

	groups := s.Groups()
	if len(groups) != 2 {
		t.Fatalf("expected 2 groups, got %d: %v", len(groups), groups)
	}
	// Sorted alphabetically.
	if groups[0] != "prod" || groups[1] != "staging" {
		t.Fatalf("expected [prod, staging], got %v", groups)
	}
}

func TestFilterByGroup(t *testing.T) {
	s := newTestStore(t)
	s.Add(Host{Alias: "a", Hostname: "1.1.1.1", Users: []string{"r"}, Group: "prod"})
	s.Add(Host{Alias: "b", Hostname: "2.2.2.2", Users: []string{"r"}, Group: "staging"})

	prod := s.FilterByGroup("prod")
	if len(prod) != 1 || prod[0].Alias != "a" {
		t.Fatal("FilterByGroup mismatch")
	}
}

func TestConnTimeoutDuration(t *testing.T) {
	h := Host{ConnTimeout: 0}
	if h.ConnTimeoutDuration().Seconds() != 10 {
		t.Fatal("default timeout should be 10s")
	}

	h.ConnTimeout = 30
	if h.ConnTimeoutDuration().Seconds() != 30 {
		t.Fatal("custom timeout should be 30s")
	}
}

func TestTouchConnected(t *testing.T) {
	s := newTestStore(t)
	s.Add(Host{Alias: "tc", Hostname: "1.1.1.1", Users: []string{"r"}})

	id := s.Hosts[0].ID
	s.TouchConnected(id)

	if s.Hosts[0].LastConnectedAt == "" {
		t.Fatal("LastConnectedAt should be set")
	}
}

func TestTouchConnectedMissingHost(t *testing.T) {
	s := newTestStore(t)
	err := s.TouchConnected("missing")
	if !errors.Is(err, ErrHostNotFound) {
		t.Fatalf("expected ErrHostNotFound, got %v", err)
	}
}

func TestExportImport(t *testing.T) {
	s1 := newTestStore(t)
	s1.Add(Host{Alias: "exp1", Hostname: "1.1.1.1", Users: []string{"root"}, Group: "test", AuthType: "password", EncPassword: []byte{1, 2, 3}})
	s1.Add(Host{Alias: "exp2", Hostname: "2.2.2.2", Users: []string{"admin"}, Tags: []string{"db"}})

	data, err := s1.Export()
	if err != nil {
		t.Fatal(err)
	}

	// Verify it's valid JSON.
	var hosts []Host
	if err := json.Unmarshal(data, &hosts); err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 {
		t.Fatalf("expected 2 exported hosts, got %d", len(hosts))
	}

	// Import into a new store.
	s2 := newTestStore(t)
	added, err := s2.Import(data)
	if err != nil {
		t.Fatal(err)
	}
	if added != 2 {
		t.Fatalf("expected 2 imported, got %d", added)
	}
	if len(s2.Hosts[0].EncPassword) != 0 {
		t.Fatal("import should clear encrypted passwords from external data")
	}

	// Import again — should skip duplicates.
	added2, err := s2.Import(data)
	if err != nil {
		t.Fatal(err)
	}
	if added2 != 0 {
		t.Fatalf("expected 0 duplicates imported, got %d", added2)
	}
}

func TestImportInvalidJSON(t *testing.T) {
	s := newTestStore(t)
	_, err := s.Import([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestFilePermissions(t *testing.T) {
	dir := t.TempDir()
	s, _ := NewStore(dir)
	s.Add(Host{Alias: "perm", Hostname: "1.1.1.1", Users: []string{"root"}})

	info, err := os.Stat(filepath.Join(dir, "hosts.json"))
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0600 {
		t.Fatalf("expected 0600 permissions, got %04o", perm)
	}
}

func TestGenID(t *testing.T) {
	ids := make(map[string]bool)
	for i := 0; i < 100; i++ {
		id, err := genID()
		if err != nil {
			t.Fatal(err)
		}
		if len(id) != 16 {
			t.Fatalf("expected 16 char hex ID, got %d chars: %s", len(id), id)
		}
		if ids[id] {
			t.Fatalf("duplicate ID generated: %s", id)
		}
		ids[id] = true
	}
}
