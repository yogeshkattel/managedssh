package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

const (
	verifierPlaintext = "managedssh-vault-ok"
	argonTime         = 3
	argonMemory       = 128 * 1024
	argonThreads      = 4
	argonKeyLen       = 32
	saltLen           = 16
)

// AAD context tags prevent ciphertext from being transplanted between roles.
var (
	aadVaultVerifier = []byte("managedssh:vault-verifier")
	aadHostPassword  = []byte("managedssh:host-password")
)

var ErrWrongPassword = errors.New("incorrect master key")

// Brute-force protection errors.
var ErrAccountLocked = errors.New("too many failed attempts, account locked")
var ErrInvalidProfileName = errors.New("invalid profile name")

// activeProfile holds the currently selected profile name.
// Empty string means "default" (legacy single-user mode).
var activeProfile string

type meta struct {
	Salt     []byte `json:"salt"`
	Nonce    []byte `json:"nonce"`
	Verifier []byte `json:"verifier"`
}

type rotationBackup struct {
	Vault []byte `json:"vault"`
	Hosts []byte `json:"hosts,omitempty"`
}

type lockoutFileState struct {
	Failures int       `json:"failures"`
	LockedAt time.Time `json:"locked_at,omitempty"`
}

// ------------------------------------------------------------------
// Brute-force protection
// ------------------------------------------------------------------

const (
	maxFailedAttempts = 5
	lockoutDuration   = 5 * time.Minute
)

var lockoutMu sync.Mutex

// checkLockout returns an error if the account is currently locked.
func checkLockout() error {
	lockoutMu.Lock()
	defer lockoutMu.Unlock()

	state, err := readLockoutState()
	if err != nil {
		return err
	}

	if state.Failures >= maxFailedAttempts {
		if time.Since(state.LockedAt) < lockoutDuration {
			remaining := lockoutDuration - time.Since(state.LockedAt)
			return fmt.Errorf("%w — try again in %s", ErrAccountLocked, remaining.Round(time.Second))
		}
		return clearLockoutState()
	}
	return nil
}

func recordFailure() error {
	lockoutMu.Lock()
	defer lockoutMu.Unlock()

	state, err := readLockoutState()
	if err != nil {
		return err
	}
	state.Failures++
	if state.Failures >= maxFailedAttempts && state.LockedAt.IsZero() {
		state.LockedAt = time.Now()
	}
	return writeLockoutState(state)
}

func resetFailures() error {
	lockoutMu.Lock()
	defer lockoutMu.Unlock()
	return clearLockoutState()
}

// ------------------------------------------------------------------
// Profile management
// ------------------------------------------------------------------

// SetProfile sets the active profile name. Empty = "default".
func SetProfile(name string) {
	activeProfile = strings.TrimSpace(name)
}

// ActiveProfile returns the current profile name (empty = default).
func ActiveProfile() string {
	return activeProfile
}

// ListProfiles returns all available profile names found in the config dir.
func ListProfiles() ([]string, error) {
	baseDir, err := baseConfigDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var profiles []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		name := e.Name()
		// Check if this dir contains a vault.json.
		vaultPath := filepath.Join(baseDir, name, "vault.json")
		if _, err := os.Stat(vaultPath); err == nil {
			if name == "default" {
				profiles = append([]string{"default"}, profiles...)
			} else {
				profiles = append(profiles, name)
			}
		}
	}
	// Also check for legacy vault.json directly in baseDir.
	legacyPath := filepath.Join(baseDir, "vault.json")
	if _, err := os.Stat(legacyPath); err == nil {
		hasDefault := false
		for _, p := range profiles {
			if p == "default" {
				hasDefault = true
				break
			}
		}
		if !hasDefault {
			profiles = append([]string{"default"}, profiles...)
		}
	}
	return profiles, nil
}

func baseConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "managedssh"), nil
}

// Dir returns the data directory for the active profile.
func Dir() (string, error) {
	base, err := baseConfigDir()
	if err != nil {
		return "", err
	}
	if activeProfile == "" || activeProfile == "default" {
		return base, nil
	}
	if err := ValidateProfileName(activeProfile); err != nil {
		return "", err
	}
	return filepath.Join(base, activeProfile), nil
}

// ValidateProfileName rejects empty and path-like profile names.
func ValidateProfileName(name string) error {
	name = strings.TrimSpace(name)
	switch {
	case name == "":
		return fmt.Errorf("%w: profile name is required", ErrInvalidProfileName)
	case name == "." || name == "..":
		return fmt.Errorf("%w: profile name cannot be %q", ErrInvalidProfileName, name)
	case strings.ContainsRune(name, '/'), strings.ContainsRune(name, '\\'), strings.Contains(name, ".."):
		return fmt.Errorf("%w: profile name cannot contain path separators", ErrInvalidProfileName)
	default:
		return nil
	}
}

func metaPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vault.json"), nil
}

func hostsPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "hosts.json"), nil
}

func rotationPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "rotation.json"), nil
}

func lockoutPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "lockout.json"), nil
}

func Exists() (bool, error) {
	p, err := metaPath()
	if err != nil {
		return false, err
	}
	_, err = os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

func deriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
}

func encryptBytes(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce = make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	ciphertext = gcm.Seal(nil, nonce, plaintext, aad)
	return nonce, ciphertext, nil
}

func decryptBytes(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

// atomicWrite writes data to a temporary file then renames it into
// place so a crash never leaves a truncated file.
func atomicWrite(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func writeOrRemove(path string, data []byte, perm os.FileMode) error {
	if len(data) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return atomicWrite(path, data, perm)
}

func readOptionalFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	return data, err
}

func readLockoutState() (lockoutFileState, error) {
	p, err := lockoutPath()
	if err != nil {
		return lockoutFileState{}, err
	}

	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return lockoutFileState{}, nil
	}
	if err != nil {
		return lockoutFileState{}, err
	}

	var state lockoutFileState
	if err := json.Unmarshal(data, &state); err != nil {
		return lockoutFileState{}, err
	}
	return state, nil
}

func writeLockoutState(state lockoutFileState) error {
	dir, err := Dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	p, err := lockoutPath()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(p, data, 0600)
}

func clearLockoutState() error {
	p, err := lockoutPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Create initialises a new vault with the given master password and
// returns the derived 256-bit encryption key.
func Create(password string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	key := deriveKey([]byte(password), salt)
	nonce, ciphertext, err := encryptBytes(key, []byte(verifierPlaintext), aadVaultVerifier)
	if err != nil {
		return nil, err
	}

	m := meta{Salt: salt, Nonce: nonce, Verifier: ciphertext}

	dir, err := Dir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}

	p, err := metaPath()
	if err != nil {
		return nil, err
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(p, data, 0600); err != nil {
		return nil, err
	}

	return key, nil
}

// Unlock verifies the master password against the stored vault and
// returns the derived encryption key on success.
func Unlock(password string) ([]byte, error) {
	if err := checkLockout(); err != nil {
		return nil, err
	}

	p, err := metaPath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var m meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	key := deriveKey([]byte(password), m.Salt)
	plain, err := decryptBytes(key, m.Nonce, m.Verifier, aadVaultVerifier)
	if err != nil {
		if recErr := recordFailure(); recErr != nil {
			return nil, fmt.Errorf("%w: failed to persist lockout state: %v", ErrWrongPassword, recErr)
		}
		return nil, ErrWrongPassword
	}
	if string(plain) != verifierPlaintext {
		if recErr := recordFailure(); recErr != nil {
			return nil, fmt.Errorf("%w: failed to persist lockout state: %v", ErrWrongPassword, recErr)
		}
		return nil, ErrWrongPassword
	}
	if err := resetFailures(); err != nil {
		return nil, fmt.Errorf("failed to reset lockout state: %w", err)
	}
	return key, nil
}

// BuildPasswordMetadata derives a new key and returns serialized vault metadata
// for the supplied master password without writing it to disk.
func BuildPasswordMetadata(newPassword string) ([]byte, []byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, nil, err
	}

	newKey := deriveKey([]byte(newPassword), salt)
	nonce, ciphertext, err := encryptBytes(newKey, []byte(verifierPlaintext), aadVaultVerifier)
	if err != nil {
		return nil, nil, err
	}

	m := meta{Salt: salt, Nonce: nonce, Verifier: ciphertext}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, nil, err
	}

	return newKey, data, nil
}

// WriteMetadata persists serialized vault metadata to the active profile.
func WriteMetadata(data []byte) error {
	p, err := metaPath()
	if err != nil {
		return err
	}
	return atomicWrite(p, data, 0600)
}

// CreateRotationBackup captures the current vault and hosts files so a failed
// key rotation can be rolled back on the next launch.
func CreateRotationBackup() error {
	vaultPath, err := metaPath()
	if err != nil {
		return err
	}
	vaultData, err := os.ReadFile(vaultPath)
	if err != nil {
		return err
	}

	hostFile, err := hostsPath()
	if err != nil {
		return err
	}
	hostsData, err := readOptionalFile(hostFile)
	if err != nil {
		return err
	}

	backup := rotationBackup{Vault: vaultData, Hosts: hostsData}
	data, err := json.Marshal(backup)
	if err != nil {
		return err
	}

	p, err := rotationPath()
	if err != nil {
		return err
	}
	return atomicWrite(p, data, 0600)
}

// RecoverPendingRotation restores the pre-rotation state after an interrupted
// master-key change. If no backup exists, it does nothing.
func RecoverPendingRotation() error {
	p, err := rotationPath()
	if err != nil {
		return err
	}

	data, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}

	var backup rotationBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return err
	}

	vaultPath, err := metaPath()
	if err != nil {
		return err
	}
	if err := writeOrRemove(vaultPath, backup.Vault, 0600); err != nil {
		return err
	}

	hostFile, err := hostsPath()
	if err != nil {
		return err
	}
	if err := writeOrRemove(hostFile, backup.Hosts, 0600); err != nil {
		return err
	}

	return os.Remove(p)
}

// ClearRotationBackup removes any pending rotation backup for the active
// profile. Missing files are ignored.
func ClearRotationBackup() error {
	p, err := rotationPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ChangePassword updates only the vault metadata and returns the new derived
// key. Callers that also store encrypted secrets must rewrite those separately.
func ChangePassword(oldKey []byte, newPassword string) ([]byte, error) {
	_ = oldKey
	newKey, data, err := BuildPasswordMetadata(newPassword)
	if err != nil {
		return nil, err
	}
	if err := WriteMetadata(data); err != nil {
		return nil, err
	}
	return newKey, nil
}

// ReEncrypt decrypts data with oldKey and re-encrypts with newKey.
func ReEncrypt(oldKey, newKey, blob []byte) ([]byte, error) {
	plain, err := Decrypt(oldKey, blob)
	if err != nil {
		return nil, err
	}
	return Encrypt(newKey, plain)
}

// Encrypt encrypts arbitrary data with the given key using the
// host-password AAD context. The nonce is prepended to the ciphertext.
func Encrypt(key, plaintext []byte) ([]byte, error) {
	nonce, ct, err := encryptBytes(key, plaintext, aadHostPassword)
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

// Decrypt decrypts a blob previously produced by Encrypt.
func Decrypt(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("ciphertext too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], aadHostPassword)
}

// ZeroKey overwrites a key slice with zeros (best-effort in Go).
func ZeroKey(key []byte) {
	for i := range key {
		key[i] = 0
	}
}
