package host

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Host struct {
	ID          string `json:"id"`
	Alias       string `json:"alias"`
	Hostname    string `json:"hostname"`
	User        string `json:"user"`
	Port        int    `json:"port"`
	AuthType    string `json:"auth_type"`
	EncPassword []byte `json:"enc_password,omitempty"`
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
	s.Hosts = append(s.Hosts, h)
	return s.Save()
}

func (s *Store) Update(id string, h Host) error {
	for i, existing := range s.Hosts {
		if existing.ID == id {
			h.ID = id
			s.Hosts[i] = h
			return s.Save()
		}
	}
	return nil
}

func (s *Store) Delete(id string) error {
	for i, h := range s.Hosts {
		if h.ID == id {
			s.Hosts = append(s.Hosts[:i], s.Hosts[i+1:]...)
			return s.Save()
		}
	}
	return nil
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
		if strings.Contains(strings.ToLower(h.Alias), q) ||
			strings.Contains(strings.ToLower(h.Hostname), q) ||
			strings.Contains(strings.ToLower(h.User), q) {
			out = append(out, h)
		}
	}
	return out
}
