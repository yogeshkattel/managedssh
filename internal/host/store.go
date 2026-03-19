package host

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var ErrHostNotFound = errors.New("host not found")

type Host struct {
	ID              string   `json:"id"`
	Alias           string   `json:"alias"`
	Hostname        string   `json:"hostname"`
	User            string   `json:"user,omitempty"`
	Users           []string `json:"users,omitempty"`
	Port            int      `json:"port"`
	AuthType        string   `json:"auth_type"`
	EncPassword     []byte   `json:"enc_password,omitempty"`
	Group           string   `json:"group,omitempty"`
	Tags            []string `json:"tags,omitempty"`
	ConnTimeout     int      `json:"conn_timeout,omitempty"` // seconds, 0 = default (10s)
	Notes           string   `json:"notes,omitempty"`
	CreatedAt       string   `json:"created_at,omitempty"`
	LastConnectedAt string   `json:"last_connected_at,omitempty"`
}

// ConnTimeoutDuration returns the connection timeout as a time.Duration.
func (h Host) ConnTimeoutDuration() time.Duration {
	if h.ConnTimeout > 0 {
		return time.Duration(h.ConnTimeout) * time.Second
	}
	return 10 * time.Second
}

type Store struct {
	path  string
	Hosts []Host `json:"hosts"`
}

func genID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating host ID: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func NewStore(dir string) (*Store, error) {
	p := filepath.Join(dir, "hosts.json")
	s := &Store{path: p}

	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, s); err != nil {
		return nil, err
	}
	for i := range s.Hosts {
		s.Hosts[i].Normalize()
	}
	return s, nil
}

func (s *Store) Save() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *Store) Add(h Host) error {
	if h.ID == "" {
		id, err := genID()
		if err != nil {
			return err
		}
		h.ID = id
	}
	if h.Port == 0 {
		h.Port = 22
	}
	if h.CreatedAt == "" {
		h.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	h.Normalize()
	s.Hosts = append(s.Hosts, h)
	return s.Save()
}

func (s *Store) Update(id string, h Host) error {
	for i, existing := range s.Hosts {
		if existing.ID == id {
			h.ID = id
			h.Normalize()
			s.Hosts[i] = h
			return s.Save()
		}
	}
	return fmt.Errorf("%w: %s", ErrHostNotFound, id)
}

func (s *Store) Delete(id string) error {
	for i, h := range s.Hosts {
		if h.ID == id {
			s.Hosts = append(s.Hosts[:i], s.Hosts[i+1:]...)
			return s.Save()
		}
	}
	return fmt.Errorf("%w: %s", ErrHostNotFound, id)
}

func (s *Store) Filter(query string) []Host {
	if query == "" {
		out := make([]Host, len(s.Hosts))
		copy(out, s.Hosts)
		return out
	}
	q := strings.ToLower(query)
	var out []Host
	for _, h := range s.Hosts {
		users := strings.ToLower(strings.Join(h.UserList(), " "))
		tags := strings.ToLower(strings.Join(h.Tags, " "))
		group := strings.ToLower(h.Group)
		if strings.Contains(strings.ToLower(h.Alias), q) ||
			strings.Contains(strings.ToLower(h.Hostname), q) ||
			strings.Contains(users, q) ||
			strings.Contains(group, q) ||
			strings.Contains(tags, q) {
			out = append(out, h)
		}
	}
	return out
}

func (h Host) UserList() []string {
	users := normalizeUsers(h.Users)
	if len(users) > 0 {
		return users
	}
	if h.User == "" {
		return nil
	}
	return normalizeUsers([]string{h.User})
}

func (h *Host) Normalize() {
	h.Users = h.UserList()
	if len(h.Users) > 0 {
		h.User = h.Users[0]
		return
	}
	h.User = ""
}

func normalizeUsers(users []string) []string {
	seen := make(map[string]struct{}, len(users))
	var out []string
	for _, user := range users {
		user = strings.TrimSpace(user)
		if user == "" {
			continue
		}
		if _, ok := seen[user]; ok {
			continue
		}
		seen[user] = struct{}{}
		out = append(out, user)
	}
	return out
}

// TouchConnected stamps the host with the current UTC time.
func (s *Store) TouchConnected(id string) error {
	for i, h := range s.Hosts {
		if h.ID == id {
			s.Hosts[i].LastConnectedAt = time.Now().UTC().Format(time.RFC3339)
			return s.Save()
		}
	}
	return fmt.Errorf("%w: %s", ErrHostNotFound, id)
}

// Groups returns all unique group names sorted alphabetically.
func (s *Store) Groups() []string {
	seen := make(map[string]struct{})
	for _, h := range s.Hosts {
		g := strings.TrimSpace(h.Group)
		if g != "" {
			seen[g] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for g := range seen {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

// FilterByGroup returns hosts matching the given group (case-insensitive).
func (s *Store) FilterByGroup(group string) []Host {
	g := strings.ToLower(strings.TrimSpace(group))
	var out []Host
	for _, h := range s.Hosts {
		if strings.ToLower(strings.TrimSpace(h.Group)) == g {
			out = append(out, h)
		}
	}
	return out
}

// Export serializes all hosts to JSON bytes for backup.
func (s *Store) Export() ([]byte, error) {
	return json.MarshalIndent(s.Hosts, "", "  ")
}

// Import merges hosts from JSON data, skipping duplicates by alias+hostname.
// Encrypted passwords are cleared because ciphertext is only valid inside the
// vault that produced it.
func (s *Store) Import(data []byte) (int, error) {
	var incoming []Host
	if err := json.Unmarshal(data, &incoming); err != nil {
		return 0, fmt.Errorf("invalid import data: %w", err)
	}

	existing := make(map[string]struct{})
	for _, h := range s.Hosts {
		key := strings.ToLower(h.Alias) + "|" + strings.ToLower(h.Hostname)
		existing[key] = struct{}{}
	}

	added := 0
	for _, h := range incoming {
		key := strings.ToLower(h.Alias) + "|" + strings.ToLower(h.Hostname)
		if _, ok := existing[key]; ok {
			continue
		}
		id, err := genID()
		if err != nil {
			return added, err
		}
		h.ID = id
		if h.Port == 0 {
			h.Port = 22
		}
		h.EncPassword = nil
		h.Normalize()
		s.Hosts = append(s.Hosts, h)
		existing[key] = struct{}{}
		added++
	}
	if added > 0 {
		if err := s.Save(); err != nil {
			return added, err
		}
	}
	return added, nil
}
