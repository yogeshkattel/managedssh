package keymgr

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// ValidateKeyName ensures key names stay within ~/.ssh and use a safe subset.
func ValidateKeyName(name string) error {
	if name == "" {
		return fmt.Errorf("key name is required")
	}
	if filepath.Base(name) != name || name == "." || name == ".." {
		return fmt.Errorf("key name must not contain path separators")
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-', c == '_', c == '.':
		default:
			return fmt.Errorf("key name contains unsupported character %q", c)
		}
	}
	return nil
}

// KeyPair holds a generated SSH key pair.
type KeyPair struct {
	Name       string
	PrivateKey []byte
	PublicKey  []byte
}

// ListKeys returns all key file stems found in ~/.ssh/.
func ListKeys() ([]string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	sshDir := filepath.Join(home, ".ssh")

	entries, err := os.ReadDir(sshDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var keys []string
	seen := make(map[string]bool)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		// Look for .pub files and infer the key name.
		if filepath.Ext(name) == ".pub" {
			stem := name[:len(name)-4]
			privPath := filepath.Join(sshDir, stem)
			if _, err := os.Stat(privPath); err == nil {
				if !seen[stem] {
					keys = append(keys, stem)
					seen[stem] = true
				}
			}
		}
	}
	return keys, nil
}

// GenerateEd25519 creates a new Ed25519 SSH key pair and saves it to ~/.ssh/.
func GenerateEd25519(name, comment string) (*KeyPair, error) {
	if err := ValidateKeyName(name); err != nil {
		return nil, err
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return nil, err
	}

	privPath := filepath.Join(sshDir, name)
	pubPath := privPath + ".pub"

	// Check if key already exists.
	if _, err := os.Stat(privPath); err == nil {
		return nil, fmt.Errorf("key %q already exists at %s", name, privPath)
	}

	// Generate Ed25519 key pair.
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}

	// Marshal private key to PEM.
	privBytes, err := ssh.MarshalPrivateKey(privKey, comment)
	if err != nil {
		return nil, fmt.Errorf("marshaling private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(privBytes)

	// Marshal public key to authorized_keys format.
	sshPub, err := ssh.NewPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("creating SSH public key: %w", err)
	}
	pubBytes := ssh.MarshalAuthorizedKey(sshPub)
	if comment != "" {
		// ssh.MarshalAuthorizedKey already adds a trailing newline.
		// Insert comment before the newline.
		pubBytes = []byte(fmt.Sprintf("%s %s\n", string(pubBytes[:len(pubBytes)-1]), comment))
	}

	// Write files with correct permissions.
	if err := os.WriteFile(privPath, privPEM, 0600); err != nil {
		return nil, fmt.Errorf("writing private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pubBytes, 0644); err != nil {
		os.Remove(privPath)
		return nil, fmt.Errorf("writing public key: %w", err)
	}

	return &KeyPair{
		Name:       name,
		PrivateKey: privPEM,
		PublicKey:  pubBytes,
	}, nil
}

// ReadPublicKey reads the public key for a given key name.
func ReadPublicKey(name string) ([]byte, error) {
	if err := ValidateKeyName(name); err != nil {
		return nil, err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	pubPath := filepath.Join(home, ".ssh", name+".pub")
	return os.ReadFile(pubPath)
}

// DeleteKey removes a key pair from ~/.ssh/.
func DeleteKey(name string) error {
	if err := ValidateKeyName(name); err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	sshDir := filepath.Join(home, ".ssh")
	privPath := filepath.Join(sshDir, name)
	pubPath := privPath + ".pub"

	privErr := os.Remove(privPath)
	pubErr := os.Remove(pubPath)

	if privErr != nil && !os.IsNotExist(privErr) {
		return privErr
	}
	if pubErr != nil && !os.IsNotExist(pubErr) {
		return pubErr
	}
	return nil
}
