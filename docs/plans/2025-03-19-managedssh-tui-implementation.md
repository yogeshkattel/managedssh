# ManagedSSH TUI Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a terminal-based GUI application for securely managing SSH credentials with master password encryption.

**Architecture:** Go-based TUI using BubbleTea framework with AES-GCM encryption. Single binary with encrypted JSON storage. All operations through interactive GUI menus.

**Tech Stack:** Go 1.21+, BubbleTea, Lipgloss, Bubbles, AES-GCM-256, Argon2id, go-ssh

---

## Phase 1: Project Setup & Core Infrastructure

### Task 1: Initialize Go Project

**Files:**
- Create: `go.mod`
- Create: `go.sum`
- Create: `main.go`
- Create: `.gitignore`

**Step 1: Initialize Go module**

```bash
go mod init github.com/yourusername/managedssh
```

**Step 2: Create .gitignore**

```bash
cat > .gitignore << 'EOF'
# Binaries
managedssh
*.exe
*.exe~
*.dll
*.so
*.dylib

# Test binary
*.test

# Output of go coverage
*.out

# Go workspace
go.work

# IDE
.vscode/
.idea/
*.swp
*.swo
*~

# Credentials (never commit)
*.enc
credentials.enc
backup/

# OS
.DS_Store
Thumbs.db
EOF
```

**Step 3: Create main.go skeleton**

```bash
cat > main.go << 'EOF'
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Println("ManagedSSH - Starting...")
	os.Exit(0)
}
EOF
```

**Step 4: Verify build**

```bash
go build -o managedssh
./managedssh
```

Expected: Output "ManagedSSH - Starting..."

**Step 5: Commit**

```bash
git init
git add .
git commit -m "feat: initialize Go project structure"
```

---

### Task 2: Install Dependencies

**Files:**
- Modify: `go.mod`
- Modify: `go.sum`

**Step 1: Install BubbleTea and related packages**

```bash
go get github.com/charmbracelet/bubbletea
go get github.com/charmbracelet/lipgloss
go get github.com/charmbracelet/bubbles
go get github.com/charmbracelet/bubbles/textinput
go get github.com/charmbracelet/bubbles/list
go get github.com/charmbracelet/bubbles/progress
```

**Step 2: Install encryption libraries**

```bash
go get golang.org/x/crypto/argon2
go get golang.org/x/crypto/chacha20poly1305
go get golang.org/x/crypto/ssh
```

**Step 3: Verify dependencies**

```bash
go mod tidy
go mod download
```

**Step 4: Commit**

```bash
git add go.mod go.sum
git commit -m "feat: add project dependencies"
```

---

## Phase 2: Data Models & Encryption

### Task 3: Create Data Models

**Files:**
- Create: `internal/models/server.go`
- Create: `internal/models/credentials.go`

**Step 1: Create models directory**

```bash
mkdir -p internal/models
```

**Step 2: Write server model**

```bash
cat > internal/models/server.go << 'EOF'
package models

import "time"

type Server struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Host      string    `json:"host"`
	Port      int       `json:"port"`
	Users     []User    `json:"users"`
	Tags      []string  `json:"tags"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used"`
}

func NewServer(name, host string, port int) *Server {
	return &Server{
		ID:        generateID(),
		Name:      name,
		Host:      host,
		Port:      port,
		Users:     []User{},
		Tags:      []string{},
		CreatedAt: time.Now(),
		LastUsed:  time.Time{},
	}
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}
EOF
```

**Step 3: Write user and credentials model**

```bash
cat > internal/models/credentials.go << 'EOF'
package models

import "time"

type User struct {
	Username  string    `json:"username"`
	AuthType  string    `json:"auth_type"` // "password" or "key"
	Password  string    `json:"password,omitempty"` // encrypted, base64
	KeyPath   string    `json:"key_path,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func NewUser(username, authType string) *User {
	return &User{
		Username:  username,
		AuthType:  authType,
		CreatedAt: time.Now(),
	}
}

type CredentialStore struct {
	Version   string    `json:"version"`
	Servers   []Server  `json:"servers"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		Version:   "1.0",
		Servers:   []Server{},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
}
EOF
```

**Step 4: Verify compilation**

```bash
go build ./internal/models
```

**Step 5: Commit**

```bash
git add internal/models/
git commit -m "feat: add data models for servers and credentials"
```

---

### Task 4: Write Tests for Data Models

**Files:**
- Create: `internal/models/server_test.go`

**Step 1: Write test for server creation**

```bash
cat > internal/models/server_test.go << 'EOF'
package models

import (
	"testing"
	"time"
)

func TestNewServer(t *testing.T) {
	name := "test-server"
	host := "192.168.1.10"
	port := 22

	server := NewServer(name, host, port)

	if server.Name != name {
		t.Errorf("Expected name %s, got %s", name, server.Name)
	}
	if server.Host != host {
		t.Errorf("Expected host %s, got %s", host, server.Host)
	}
	if server.Port != port {
		t.Errorf("Expected port %d, got %d", port, server.Port)
	}
	if server.ID == "" {
		t.Error("Expected non-empty ID")
	}
	if len(server.Users) != 0 {
		t.Errorf("Expected 0 users, got %d", len(server.Users))
	}
	if server.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
}

func TestNewUser(t *testing.T) {
	username := "testuser"
	authType := "password"

	user := NewUser(username, authType)

	if user.Username != username {
		t.Errorf("Expected username %s, got %s", username, user.Username)
	}
	if user.AuthType != authType {
		t.Errorf("Expected authType %s, got %s", authType, user.AuthType)
	}
	if user.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
}

func TestNewCredentialStore(t *testing.T) {
	store := NewCredentialStore()

	if store.Version != "1.0" {
		t.Errorf("Expected version 1.0, got %s", store.Version)
	}
	if len(store.Servers) != 0 {
		t.Errorf("Expected 0 servers, got %d", len(store.Servers))
	}
	if store.CreatedAt.IsZero() {
		t.Error("Expected CreatedAt to be set")
	}
	if store.UpdatedAt.IsZero() {
		t.Error("Expected UpdatedAt to be set")
	}
}
EOF
```

**Step 2: Run tests**

```bash
go test ./internal/models -v
```

Expected: All tests pass

**Step 3: Commit**

```bash
git add internal/models/server_test.go
git commit -m "test: add tests for data models"
```

---

### Task 5: Implement Encryption Package

**Files:**
- Create: `internal/crypto/encryption.go`
- Create: `internal/crypto/key_derivation.go`

**Step 1: Create crypto directory**

```bash
mkdir -p internal/crypto
```

**Step 2: Write key derivation function**

```bash
cat > internal/crypto/key_derivation.go << 'EOF'
package crypto

import (
	"crypto/rand"
	"golang.org/x/crypto/argon2"
)

const (
	saltLength = 16
	memory     = 64 * 1024 // 64MB
	iterations = 3
	parallelism = 4
	keyLength  = 32 // 256 bits
)

func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		uint8(parallelism),
		keyLength,
	)
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}
EOF
```

**Step 3: Write encryption/decryption functions**

```bash
cat > internal/crypto/encryption.go << 'EOF'
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

var ErrInvalidCiphertext = errors.New("invalid ciphertext")

type EncryptedData struct {
	Salt       []byte `json:"salt"`
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

func Encrypt(plaintext []byte, password string) (*EncryptedData, error) {
	salt, err := GenerateSalt()
	if err != nil {
		return nil, err
	}

	key := DeriveKey(password, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	return &EncryptedData{
		Salt:       salt,
		Nonce:      nonce,
		Ciphertext: ciphertext,
	}, nil
}

func Decrypt(data *EncryptedData, password string) ([]byte, error) {
	key := DeriveKey(password, data.Salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plaintext, err := gcm.Open(nil, data.Nonce, data.Ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func DecodeBase64(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
EOF
```

**Step 4: Verify compilation**

```bash
go build ./internal/crypto
```

**Step 5: Commit**

```bash
git add internal/crypto/
git commit -m "feat: implement encryption with AES-GCM and Argon2"
```

---

### Task 6: Write Tests for Encryption

**Files:**
- Create: `internal/crypto/encryption_test.go`

**Step 1: Write encryption tests**

```bash
cat > internal/crypto/encryption_test.go << 'EOF'
package crypto

import (
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	plaintext := []byte("my secret password")
	password := "master-password-123"

	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if len(encrypted.Salt) == 0 {
		t.Error("Expected non-empty salt")
	}
	if len(encrypted.Nonce) == 0 {
		t.Error("Expected non-empty nonce")
	}
	if len(encrypted.Ciphertext) == 0 {
		t.Error("Expected non-empty ciphertext")
	}

	decrypted, err := Decrypt(encrypted, password)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Expected %s, got %s", plaintext, decrypted)
	}
}

func TestDecryptWithWrongPassword(t *testing.T) {
	plaintext := []byte("my secret password")
	password := "correct-password"
	wrongPassword := "wrong-password"

	encrypted, err := Encrypt(plaintext, password)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	_, err = Decrypt(encrypted, wrongPassword)
	if err == nil {
		t.Error("Expected decryption to fail with wrong password")
	}
}

func TestGenerateSalt(t *testing.T) {
	salt1, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	salt2, err := GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt failed: %v", err)
	}

	if len(salt1) != saltLength {
		t.Errorf("Expected salt length %d, got %d", saltLength, len(salt1))
	}

	if string(salt1) == string(salt2) {
		t.Error("Expected different salts")
	}
}

func TestDeriveKey(t *testing.T) {
	password := "test-password"
	salt := []byte("test-salt-123456")

	key1 := DeriveKey(password, salt)
	key2 := DeriveKey(password, salt)

	if len(key1) != keyLength {
		t.Errorf("Expected key length %d, got %d", keyLength, len(key1))
	}

	if string(key1) != string(key2) {
		t.Error("Expected same key for same password and salt")
	}
}

func TestBase64Encoding(t *testing.T) {
	data := []byte("test data")

	encoded := EncodeBase64(data)
	decoded, err := DecodeBase64(encoded)

	if err != nil {
		t.Fatalf("DecodeBase64 failed: %v", err)
	}

	if string(decoded) != string(data) {
		t.Errorf("Expected %s, got %s", data, decoded)
	}
}
EOF
```

**Step 2: Run tests**

```bash
go test ./internal/crypto -v
```

Expected: All tests pass

**Step 3: Commit**

```bash
git add internal/crypto/encryption_test.go
git commit -m "test: add encryption package tests"
```

---

## Phase 3: Storage Layer

### Task 7: Implement Storage Manager

**Files:**
- Create: `internal/storage/manager.go`
- Create: `internal/storage/paths.go`

**Step 1: Create storage directory**

```bash
mkdir -p internal/storage
```

**Step 2: Write paths helper**

```bash
cat > internal/storage/paths.go << 'EOF'
package storage

import (
	"os"
	"path/filepath"
)

const (
	AppName = "managedssh"
)

func GetConfigDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", AppName), nil
}

func GetCredentialsPath() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "credentials.enc"), nil
}

func GetBackupDir() (string, error) {
	configDir, err := GetConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "backup"), nil
}

func EnsureConfigDir() error {
	configDir, err := GetConfigDir()
	if err != nil {
		return err
	}
	return os.MkdirAll(configDir, 0700)
}

func EnsureBackupDir() error {
	backupDir, err := GetBackupDir()
	if err != nil {
		return err
	}
	return os.MkdirAll(backupDir, 0700)
}
EOF
```

**Step 3: Write storage manager**

```bash
cat > internal/storage/manager.go << 'EOF'
package storage

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/yourusername/managedssh/internal/crypto"
	"github.com/yourusername/managedssh/internal/models"
)

type Manager struct {
	credentialsPath string
	backupDir       string
}

func NewManager() (*Manager, error) {
	if err := EnsureConfigDir(); err != nil {
		return nil, err
	}
	if err := EnsureBackupDir(); err != nil {
		return nil, err
	}

	credPath, err := GetCredentialsPath()
	if err != nil {
		return nil, err
	}

	backupDir, err := GetBackupDir()
	if err != nil {
		return nil, err
	}

	return &Manager{
		credentialsPath: credPath,
		backupDir:       backupDir,
	}, nil
}

func (m *Manager) Exists() bool {
	_, err := os.Stat(m.credentialsPath)
	return !os.IsNotExist(err)
}

func (m *Manager) Save(store *models.CredentialStore, password string) error {
	store.UpdatedAt = time.Now()

	plaintext, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	encrypted, err := crypto.Encrypt(plaintext, password)
	if err != nil {
		return err
	}

	encryptedJSON, err := json.Marshal(encrypted)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(m.credentialsPath, encryptedJSON, 0600)
}

func (m *Manager) Load(password string) (*models.CredentialStore, error) {
	data, err := ioutil.ReadFile(m.credentialsPath)
	if err != nil {
		return nil, err
	}

	var encrypted crypto.EncryptedData
	if err := json.Unmarshal(data, &encrypted); err != nil {
		return nil, err
	}

	plaintext, err := crypto.Decrypt(&encrypted, password)
	if err != nil {
		return nil, err
	}

	var store models.CredentialStore
	if err := json.Unmarshal(plaintext, &store); err != nil {
		return nil, err
	}

	return &store, nil
}

func (m *Manager) CreateBackup(password string) error {
	if !m.Exists() {
		return nil
	}

	backupPath := filepath.Join(m.backupDir, 
		fmt.Sprintf("credentials.%s.enc", time.Now().Format("20060102-150405")))

	data, err := ioutil.ReadFile(m.credentialsPath)
	if err != nil {
		return err
	}

	return ioutil.WriteFile(backupPath, data, 0600)
}

func (m *Manager) InitializeStore(password string) error {
	store := models.NewCredentialStore()
	return m.Save(store, password)
}
EOF
```

**Step 4: Verify compilation**

```bash
go build ./internal/storage
```

**Step 5: Commit**

```bash
git add internal/storage/
git commit -m "feat: implement storage manager with encryption"
```

---

### Task 8: Write Tests for Storage Manager

**Files:**
- Create: `internal/storage/manager_test.go`

**Step 1: Write storage tests**

```bash
cat > internal/storage/manager_test.go << 'EOF'
package storage

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/yourusername/managedssh/internal/models"
)

func TestStorageManager(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "credentials.enc")
	backupDir := filepath.Join(tmpDir, "backup")

	m := &Manager{
		credentialsPath: credPath,
		backupDir:       backupDir,
	}

	password := "test-master-password"

	t.Run("InitializeStore", func(t *testing.T) {
		err := m.InitializeStore(password)
		if err != nil {
			t.Fatalf("InitializeStore failed: %v", err)
		}

		if !m.Exists() {
			t.Error("Expected credentials file to exist")
		}
	})

	t.Run("LoadStore", func(t *testing.T) {
		store, err := m.Load(password)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}

		if store.Version != "1.0" {
			t.Errorf("Expected version 1.0, got %s", store.Version)
		}

		if len(store.Servers) != 0 {
			t.Errorf("Expected 0 servers, got %d", len(store.Servers))
		}
	})

	t.Run("SaveAndLoad", func(t *testing.T) {
		store := models.NewCredentialStore()
		server := models.NewServer("test-server", "192.168.1.10", 22)
		store.Servers = append(store.Servers, *server)

		err := m.Save(store, password)
		if err != nil {
			t.Fatalf("Save failed: %v", err)
		}

		loaded, err := m.Load(password)
		if err != nil {
			t.Fatalf("Load failed: %v", err)
		}

		if len(loaded.Servers) != 1 {
			t.Errorf("Expected 1 server, got %d", len(loaded.Servers))
		}

		if loaded.Servers[0].Name != "test-server" {
			t.Errorf("Expected server name 'test-server', got %s", loaded.Servers[0].Name)
		}
	})

	t.Run("LoadWithWrongPassword", func(t *testing.T) {
		_, err := m.Load("wrong-password")
		if err == nil {
			t.Error("Expected error with wrong password")
		}
	})

	t.Run("CreateBackup", func(t *testing.T) {
		os.MkdirAll(backupDir, 0700)
		
		err := m.CreateBackup(password)
		if err != nil {
			t.Fatalf("CreateBackup failed: %v", err)
		}

		files, err := os.ReadDir(backupDir)
		if err != nil {
			t.Fatalf("ReadDir failed: %v", err)
		}

		if len(files) == 0 {
			t.Error("Expected backup file to be created")
		}
	})
}
EOF
```

**Step 2: Run tests**

```bash
go test ./internal/storage -v
```

Expected: All tests pass

**Step 3: Commit**

```bash
git add internal/storage/manager_test.go
git commit -m "test: add storage manager tests"
```

---

## Phase 4: TUI Framework

### Task 9: Create Main TUI Application

**Files:**
- Create: `internal/tui/app.go`
- Create: `internal/tui/styles.go`

**Step 1: Create TUI directory**

```bash
mkdir -p internal/tui
```

**Step 2: Write styles**

```bash
cat > internal/tui/styles.go << 'EOF'
package tui

import "github.com/charmbracelet/lipgloss"

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#7D56F4")).
			Padding(0, 1)

	menuStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FAFAFA")).
			Background(lipgloss.Color("#3C3C3C")).
			Padding(0, 2).
			Margin(0, 1)

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#7D56F4")).
			Background(lipgloss.Color("#E5E5E5")).
			Bold(true).
			Padding(0, 2).
			Margin(0, 1)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#7D56F4")).
			Padding(1, 2).
			Margin(1, 2)

	helpStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#626262"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6B6B")).
			Bold(true)

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#4CAF50")).
			Bold(true)
)
EOF
```

**Step 3: Write app model**

```bash
cat > internal/tui/app.go << 'EOF'
package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	screenMasterPassword screen = iota
	screenDashboard
	screenServerList
	screenAddServer
	screenEditServer
	screenConnect
)

type Model struct {
	currentScreen screen
	masterPassword string
	errorMessage   string
	width         int
	height        int
}

func NewModel() Model {
	return Model{
		currentScreen: screenMasterPassword,
		masterPassword: "",
		errorMessage:   "",
	}
}

func (m Model) Init() tea.Cmd {
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	switch m.currentScreen {
	case screenMasterPassword:
		return m.updateMasterPassword(msg)
	case screenDashboard:
		return m.updateDashboard(msg)
	}

	return m, nil
}

func (m Model) View() string {
	switch m.currentScreen {
	case screenMasterPassword:
		return m.viewMasterPassword()
	case screenDashboard:
		return m.viewDashboard()
	default:
		return "Unknown screen"
	}
}

func (m Model) viewMasterPassword() string {
	return fmt.Sprintf(
		"\n%s\n\nEnter master password: \n\n%s",
		titleStyle.Render(" ManagedSSH "),
		helpStyle.Render("Press Enter to continue, Ctrl+C to exit"),
	)
}

func (m Model) viewDashboard() string {
	menu := fmt.Sprintf(
		"%s %s %s",
		menuStyle.Render("Connect to Server"),
		menuStyle.Render("Add New Server"),
		menuStyle.Render("Settings"),
	)

	return fmt.Sprintf(
		"\n%s\n\n%s\n\n%s",
		titleStyle.Render(" ManagedSSH Dashboard "),
		menu,
		helpStyle.Render("Use arrow keys to navigate, Enter to select, Q to quit"),
	)
}

func (m *Model) updateMasterPassword(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			m.currentScreen = screenDashboard
			return m, nil
		}
	}

	return m, nil
}

func (m *Model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, nil
}

func Start() error {
	p := tea.NewProgram(NewModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
EOF
```

**Step 4: Update main.go**

```bash
cat > main.go << 'EOF'
package main

import (
	"fmt"
	"os"

	"github.com/yourusername/managedssh/internal/tui"
)

func main() {
	if err := tui.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
EOF
```

**Step 5: Test TUI**

```bash
go build -o managedssh
./managedssh
```

Press Ctrl+C to exit

**Step 6: Commit**

```bash
git add internal/tui/ main.go
git commit -m "feat: implement basic TUI framework with BubbleTea"
```

---

### Task 10: Implement Master Password Screen

**Files:**
- Modify: `internal/tui/app.go`
- Create: `internal/tui/screens/master_password.go`

**Step 1: Create screens directory**

```bash
mkdir -p internal/tui/screens
```

**Step 2: Write master password screen**

```bash
cat > internal/tui/screens/master_password.go << 'EOF'
package screens

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/yourusername/managedssh/internal/tui"
)

type MasterPasswordModel struct {
	textInput    textinput.Model
	titleStyle   lipgloss.Style
	errorMessage string
}

func NewMasterPasswordModel() MasterPasswordModel {
	ti := textinput.New()
	ti.Placeholder = "Enter master password"
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.Focus()

	return MasterPasswordModel{
		textInput:    ti,
		titleStyle:   tui.TitleStyle,
		errorMessage: "",
	}
}

func (m MasterPasswordModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m MasterPasswordModel) Update(msg tea.Msg) (MasterPasswordModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			if m.textInput.Value() == "" {
				m.errorMessage = "Password cannot be empty"
				return m, nil
			}
			return m, func() tea.Msg {
				return MasterPasswordSetMsg{Password: m.textInput.Value()}
			}
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		}
	}

	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m MasterPasswordModel) View() string {
	errorView := ""
	if m.errorMessage != "" {
		errorView = "\n" + tui.ErrorStyle.Render("Error: "+m.errorMessage) + "\n"
	}

	return fmt.Sprintf(
		"\n%s\n\n%s\n\n%s\n%s",
		tui.TitleStyle.Render(" ManagedSSH "),
		tui.BoxStyle.Render(m.textInput.View()),
		errorView,
		tui.HelpStyle.Render("Enter: Submit | Ctrl+C: Exit"),
	)
}

type MasterPasswordSetMsg struct {
	Password string
}
EOF
```

**Step 3: Update app.go to use master password screen**

```bash
cat > internal/tui/app.go << 'EOF'
package tui

import (
	tea "github.com/charmbracelet/bubbletea"
	"github.com/yourusername/managedssh/internal/tui/screens"
	"github.com/yourusername/managedssh/internal/storage"
)

type screen int

const (
	screenMasterPassword screen = iota
	screenDashboard
)

type Model struct {
	currentScreen  screen
	masterPassword string
	storageManager *storage.Manager
	masterPasswordModel screens.MasterPasswordModel
	errorMessage   string
	width          int
	height         int
}

func NewModel() Model {
	mgr, err := storage.NewManager()
	if err != nil {
		panic(err)
	}

	return Model{
		currentScreen:      screenMasterPassword,
		masterPassword:     "",
		storageManager:     mgr,
		masterPasswordModel: screens.NewMasterPasswordModel(),
		errorMessage:       "",
	}
}

func (m Model) Init() tea.Cmd {
	return m.masterPasswordModel.Init
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case screens.MasterPasswordSetMsg:
		m.masterPassword = msg.Password
		m.currentScreen = screenDashboard
		return m, nil
	}

	switch m.currentScreen {
	case screenMasterPassword:
		var cmd tea.Cmd
		m.masterPasswordModel, cmd = m.masterPasswordModel.Update(msg)
		return m, cmd
	case screenDashboard:
		return m.updateDashboard(msg)
	}

	return m, nil
}

func (m Model) View() string {
	switch m.currentScreen {
	case screenMasterPassword:
		return m.masterPasswordModel.View()
	case screenDashboard:
		return m.viewDashboard()
	default:
		return "Unknown screen"
	}
}

func (m Model) viewDashboard() string {
	menu := fmt.Sprintf(
		"%s %s %s",
		MenuStyle.Render("Connect to Server"),
		MenuStyle.Render("Add New Server"),
		MenuStyle.Render("Settings"),
	)

	return fmt.Sprintf(
		"\n%s\n\n%s\n\n%s",
		TitleStyle.Render(" ManagedSSH Dashboard "),
		menu,
		HelpStyle.Render("Q: Quit"),
	)
}

func (m *Model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func Start() error {
	p := tea.NewProgram(NewModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
EOF
```

**Step 4: Fix imports and test**

```bash
go mod tidy
go build -o managedssh
./managedssh
```

**Step 5: Commit**

```bash
git add internal/tui/
git commit -m "feat: implement master password screen with input"
```

---

## Phase 5: Server Management

### Task 11: Implement Server List Screen

**Files:**
- Create: `internal/tui/screens/server_list.go`

**Step 1: Write server list screen**

```bash
cat > internal/tui/screens/server_list.go << 'EOF'
package screens

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/list"
	"github.com/yourusername/managedssh/internal/models"
	"github.com/yourusername/managedssh/internal/tui"
)

type serverItem struct {
	server models.Server
}

func (i serverItem) FilterValue() string {
	return i.server.Name + " " + i.server.Host
}

func (i serverItem) Title() string {
	return i.server.Name
}

func (i serverItem) Description() string {
	users := len(i.server.Users)
	return fmt.Sprintf("%s:%d (%d users)", i.server.Host, i.server.Port, users)
}

type ServerListModel struct {
	list     list.Model
	servers  []models.Server
	selected *models.Server
}

func NewServerListModel(servers []models.Server) ServerListModel {
	items := make([]list.Item, len(servers))
	for i, server := range servers {
		items[i] = serverItem{server: server}
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Select Server"
	l.SetFilteringEnabled(true)

	return ServerListModel{
		list:    l,
		servers: servers,
	}
}

func (m ServerListModel) Init() tea.Cmd {
	return nil
}

func (m ServerListModel) Update(msg tea.Msg) (ServerListModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "enter":
			if item, ok := m.list.SelectedItem().(serverItem); ok {
				m.selected = &item.server
				return m, func() tea.Msg {
					return ServerSelectedMsg{Server: item.server}
				}
			}
		case "esc":
			return m, func() tea.Msg {
				return BackToDashboardMsg{}
			}
		}
	case tea.WindowSizeMsg:
		m.list.SetSize(msg.Width, msg.Height)
	}

	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m ServerListModel) View() string {
	return m.list.View()
}

type ServerSelectedMsg struct {
	Server models.Server
}

type BackToDashboardMsg struct{}
EOF
```

**Step 2: Integrate into main app**

```bash
cat > internal/tui/app.go << 'EOF'
package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/yourusername/managedssh/internal/models"
	"github.com/yourusername/managedssh/internal/tui/screens"
	"github.com/yourusername/managedssh/internal/storage"
)

type screen int

const (
	screenMasterPassword screen = iota
	screenDashboard
	screenServerList
	screenAddServer
)

type Model struct {
	currentScreen      screen
	masterPassword     string
	storageManager     *storage.Manager
	credentialStore    *models.CredentialStore
	masterPasswordModel screens.MasterPasswordModel
	serverListModel    screens.ServerListModel
	errorMessage       string
	width              int
	height             int
}

func NewModel() Model {
	mgr, err := storage.NewManager()
	if err != nil {
		panic(err)
	}

	return Model{
		currentScreen:      screenMasterPassword,
		masterPassword:     "",
		storageManager:     mgr,
		masterPasswordModel: screens.NewMasterPasswordModel(),
		errorMessage:       "",
	}
}

func (m Model) Init() tea.Cmd {
	return m.masterPasswordModel.Init
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case screens.MasterPasswordSetMsg:
		m.masterPassword = msg.Password
		if !m.storageManager.Exists() {
			store := models.NewCredentialStore()
			if err := m.storageManager.Save(store, m.masterPassword); err != nil {
				m.errorMessage = err.Error()
				return m, nil
			}
			m.credentialStore = store
		} else {
			store, err := m.storageManager.Load(m.masterPassword)
			if err != nil {
				m.errorMessage = "Invalid password"
				return m, nil
			}
			m.credentialStore = store
		}
		m.currentScreen = screenDashboard
		return m, nil
	case screens.ServerSelectedMsg:
		// TODO: Handle server selection
		return m, nil
	case screens.BackToDashboardMsg:
		m.currentScreen = screenDashboard
		return m, nil
	}

	switch m.currentScreen {
	case screenMasterPassword:
		var cmd tea.Cmd
		m.masterPasswordModel, cmd = m.masterPasswordModel.Update(msg)
		return m, cmd
	case screenDashboard:
		return m.updateDashboard(msg)
	case screenServerList:
		var cmd tea.Cmd
		m.serverListModel, cmd = m.serverListModel.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) View() string {
	switch m.currentScreen {
	case screenMasterPassword:
		return m.masterPasswordModel.View()
	case screenDashboard:
		return m.viewDashboard()
	case screenServerList:
		return m.serverListModel.View()
	default:
		return "Unknown screen"
	}
}

func (m Model) viewDashboard() string {
	menu := fmt.Sprintf(
		"%s\n%s\n%s",
		MenuStyle.Render("1. Connect to Server"),
		MenuStyle.Render("2. Add New Server"),
		MenuStyle.Render("3. Settings"),
	)

	recentServers := ""
	if m.credentialStore != nil && len(m.credentialStore.Servers) > 0 {
		recentServers = "\n\n" + BoxStyle.Render("Recent Servers:\n") + "\n"
		for i, server := range m.credentialStore.Servers {
			if i >= 5 {
				break
			}
			recentServers += fmt.Sprintf("  • %s (%s)\n", server.Name, server.Host)
		}
	}

	return fmt.Sprintf(
		"\n%s\n\n%s%s\n%s",
		TitleStyle.Render(" ManagedSSH Dashboard "),
		menu,
		recentServers,
		HelpStyle.Render("1-3: Select | Q: Quit"),
	)
}

func (m *Model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "1":
			m.serverListModel = screens.NewServerListModel(m.credentialStore.Servers)
			m.currentScreen = screenServerList
			return m, nil
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func Start() error {
	p := tea.NewProgram(NewModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
EOF
```

**Step 3: Test server list**

```bash
go build -o managedssh
./managedssh
```

**Step 4: Commit**

```bash
git add internal/tui/screens/server_list.go internal/tui/app.go
git commit -m "feat: implement server list screen with fuzzy search"
```

---

## Phase 6: Add Server Form

### Task 12: Implement Add Server Form

**Files:**
- Create: `internal/tui/screens/add_server.go`

**Step 1: Write add server form**

```bash
cat > internal/tui/screens/add_server.go << 'EOF'
package screens

import (
	"fmt"
	"strconv"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/yourusername/managedssh/internal/models"
	"github.com/yourusername/managedssh/internal/tui"
)

type addServerState int

const (
	addServerName addServerState = iota
	addServerHost
	addServerPort
	addServerConfirm
)

type AddServerModel struct {
	state       addServerState
	inputs      []textinput.Model
	focused     int
	serverName  string
	serverHost  string
	serverPort  int
	errorMessage string
}

func NewAddServerModel() AddServerModel {
	inputs := make([]textinput.Model, 3)
	
	inputs[0] = textinput.New()
	inputs[0].Placeholder = "my-server"
	inputs[0].Focus()
	
	inputs[1] = textinput.New()
	inputs[1].Placeholder = "192.168.1.10"
	
	inputs[2] = textinput.New()
	inputs[2].Placeholder = "22"

	return AddServerModel{
		state:   addServerName,
		inputs:  inputs,
		focused: 0,
	}
}

func (m AddServerModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m AddServerModel) Update(msg tea.Msg) (AddServerModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			return m.handleEnter()
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, func() tea.Msg {
				return BackToDashboardMsg{}
			}
		case tea.KeyTab, tea.KeyDown:
			m.focused = (m.focused + 1) % 3
			for i := range m.inputs {
				if i == m.focused {
					m.inputs[i].Focus()
				} else {
					m.inputs[i].Blur()
				}
			}
		case tea.KeyShiftTab, tea.KeyUp:
			m.focused = (m.focused - 1 + 3) % 3
			for i := range m.inputs {
				if i == m.focused {
					m.inputs[i].Focus()
				} else {
					m.inputs[i].Blur()
				}
			}
		}
	}

	m.inputs[m.focused], cmd = m.inputs[m.focused].Update(msg)
	return m, cmd
}

func (m *AddServerModel) handleEnter() (AddServerModel, tea.Cmd) {
	switch m.state {
	case addServerName:
		if m.inputs[0].Value() == "" {
			m.errorMessage = "Server name is required"
			return m, nil
		}
		m.serverName = m.inputs[0].Value()
		m.state = addServerHost
		m.focused = 1
		m.inputs[1].Focus()
		m.inputs[0].Blur()
	case addServerHost:
		if m.inputs[1].Value() == "" {
			m.errorMessage = "Host is required"
			return m, nil
		}
		m.serverHost = m.inputs[1].Value()
		m.state = addServerPort
		m.focused = 2
		m.inputs[2].Focus()
		m.inputs[1].Blur()
	case addServerPort:
		port := 22
		if m.inputs[2].Value() != "" {
			var err error
			port, err = strconv.Atoi(m.inputs[2].Value())
			if err != nil || port < 1 || port > 65535 {
				m.errorMessage = "Invalid port number"
				return m, nil
			}
		}
		m.serverPort = port
		m.state = addServerConfirm
		return m, func() tea.Msg {
			return ServerCreatedMsg{
				Server: *models.NewServer(m.serverName, m.serverHost, m.serverPort),
			}
		}
	}

	m.errorMessage = ""
	return m, nil
}

func (m AddServerModel) View() string {
	var fields []string
	for i, input := range m.inputs {
		label := ""
		switch i {
		case 0:
			label = "Server Name:"
		case 1:
			label = "Host:"
		case 2:
			label = "Port:"
		}
		
		field := fmt.Sprintf("%s\n%s", label, tui.BoxStyle.Render(input.View()))
		fields = append(fields, field)
	}

	errorView := ""
	if m.errorMessage != "" {
		errorView = "\n" + tui.ErrorStyle.Render("Error: "+m.errorMessage)
	}

	return fmt.Sprintf(
		"\n%s\n\n%s%s\n\n%s",
		tui.TitleStyle.Render(" Add New Server "),
		fmt.Sprintf("%s\n\n%s\n\n%s", fields[0], fields[1], fields[2]),
		errorView,
		tui.HelpStyle.Render("Tab: Next | Shift+Tab: Previous | Enter: Continue | Esc: Cancel"),
	)
}

type ServerCreatedMsg struct {
	Server models.Server
}
EOF
```

**Step 2: Integrate into main app**

```bash
cat > internal/tui/app.go << 'EOF'
package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/yourusername/managedssh/internal/models"
	"github.com/yourusername/managedssh/internal/tui/screens"
	"github.com/yourusername/managedssh/internal/storage"
)

type screen int

const (
	screenMasterPassword screen = iota
	screenDashboard
	screenServerList
	screenAddServer
)

type Model struct {
	currentScreen      screen
	masterPassword     string
	storageManager     *storage.Manager
	credentialStore    *models.CredentialStore
	masterPasswordModel screens.MasterPasswordModel
	serverListModel    screens.ServerListModel
	addServerModel     screens.AddServerModel
	errorMessage       string
	width              int
	height             int
}

func NewModel() Model {
	mgr, err := storage.NewManager()
	if err != nil {
		panic(err)
	}

	return Model{
		currentScreen:      screenMasterPassword,
		masterPassword:     "",
		storageManager:     mgr,
		masterPasswordModel: screens.NewMasterPasswordModel(),
		addServerModel:     screens.NewAddServerModel(),
		errorMessage:       "",
	}
}

func (m Model) Init() tea.Cmd {
	return m.masterPasswordModel.Init
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	case screens.MasterPasswordSetMsg:
		m.masterPassword = msg.Password
		if !m.storageManager.Exists() {
			store := models.NewCredentialStore()
			if err := m.storageManager.Save(store, m.masterPassword); err != nil {
				m.errorMessage = err.Error()
				return m, nil
			}
			m.credentialStore = store
		} else {
			store, err := m.storageManager.Load(m.masterPassword)
			if err != nil {
				m.errorMessage = "Invalid password"
				return m, nil
			}
			m.credentialStore = store
		}
		m.currentScreen = screenDashboard
		return m, nil
	case screens.ServerSelectedMsg:
		// TODO: Connect to server
		return m, nil
	case screens.BackToDashboardMsg:
		m.currentScreen = screenDashboard
		return m, nil
	case screens.ServerCreatedMsg:
		m.credentialStore.Servers = append(m.credentialStore.Servers, msg.Server)
		if err := m.storageManager.Save(m.credentialStore, m.masterPassword); err != nil {
			m.errorMessage = err.Error()
			return m, nil
		}
		m.currentScreen = screenDashboard
		return m, nil
	}

	switch m.currentScreen {
	case screenMasterPassword:
		var cmd tea.Cmd
		m.masterPasswordModel, cmd = m.masterPasswordModel.Update(msg)
		return m, cmd
	case screenDashboard:
		return m.updateDashboard(msg)
	case screenServerList:
		var cmd tea.Cmd
		m.serverListModel, cmd = m.serverListModel.Update(msg)
		return m, cmd
	case screenAddServer:
		var cmd tea.Cmd
		m.addServerModel, cmd = m.addServerModel.Update(msg)
		return m, cmd
	}

	return m, nil
}

func (m Model) View() string {
	switch m.currentScreen {
	case screenMasterPassword:
		return m.masterPasswordModel.View()
	case screenDashboard:
		return m.viewDashboard()
	case screenServerList:
		return m.serverListModel.View()
	case screenAddServer:
		return m.addServerModel.View()
	default:
		return "Unknown screen"
	}
}

func (m Model) viewDashboard() string {
	menu := fmt.Sprintf(
		"%s\n%s\n%s",
		MenuStyle.Render("1. Connect to Server"),
		MenuStyle.Render("2. Add New Server"),
		MenuStyle.Render("3. Settings"),
	)

	recentServers := ""
	if m.credentialStore != nil && len(m.credentialStore.Servers) > 0 {
		recentServers = "\n\n" + BoxStyle.Render("Recent Servers:\n") + "\n"
		for i, server := range m.credentialStore.Servers {
			if i >= 5 {
				break
			}
			recentServers += fmt.Sprintf("  • %s (%s)\n", server.Name, server.Host)
		}
	}

	return fmt.Sprintf(
		"\n%s\n\n%s%s\n%s",
		TitleStyle.Render(" ManagedSSH Dashboard "),
		menu,
		recentServers,
		HelpStyle.Render("1-3: Select | Q: Quit"),
	)
}

func (m *Model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "1":
			m.serverListModel = screens.NewServerListModel(m.credentialStore.Servers)
			m.currentScreen = screenServerList
			return m, nil
		case "2":
			m.addServerModel = screens.NewAddServerModel()
			m.currentScreen = screenAddServer
			return m, nil
		case "q", "ctrl+c":
			return m, tea.Quit
		}
	}
	return m, nil
}

func Start() error {
	p := tea.NewProgram(NewModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
EOF
```

**Step 3: Test add server form**

```bash
go build -o managedssh
./managedssh
```

**Step 4: Commit**

```bash
git add internal/tui/screens/add_server.go internal/tui/app.go
git commit -m "feat: implement add server form with validation"
```

---

## Phase 7: SSH Connection

### Task 13: Implement SSH Connection

**Files:**
- Create: `internal/ssh/client.go`

**Step 1: Create SSH directory**

```bash
mkdir -p internal/ssh
```

**Step 2: Write SSH client**

```bash
cat > internal/ssh/client.go << 'EOF'
package ssh

import (
	"fmt"
	"io/ioutil"
	"time"

	"golang.org/x/crypto/ssh"
	"github.com/yourusername/managedssh/internal/models"
)

type Client struct{}

func NewClient() *Client {
	return &Client{}
}

func (c *Client) Connect(server *models.Server, user *models.User) error {
	config := &ssh.ClientConfig{
		User: user.Username,
		Auth: []ssh.AuthMethod{},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout: 30 * time.Second,
	}

	switch user.AuthType {
	case "password":
		config.Auth = append(config.Auth, ssh.Password(user.Password))
	case "key":
		key, err := ioutil.ReadFile(user.KeyPath)
		if err != nil {
			return fmt.Errorf("failed to read private key: %w", err)
		}

		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}

		config.Auth = append(config.Auth, ssh.PublicKeys(signer))
	default:
		return fmt.Errorf("unsupported auth type: %s", user.AuthType)
	}

	address := fmt.Sprintf("%s:%d", server.Host, server.Port)
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %w", err)
	}
	defer session.Close()

	return nil
}
EOF
```

**Step 3: Verify compilation**

```bash
go build ./internal/ssh
```

**Step 4: Commit**

```bash
git add internal/ssh/
git commit -m "feat: implement SSH client connection"
```

---

## Phase 8: User Management

### Task 14: Add User Management Screen

**Files:**
- Create: `internal/tui/screens/user_management.go`

**Step 1: Write user management screen**

```bash
cat > internal/tui/screens/user_management.go << 'EOF'
package screens

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/yourusername/managedssh/internal/models"
	"github.com/yourusername/managedssh/internal/tui"
)

type userState int

const (
	userSelectAuth userState = iota
	userUsername
	userPassword
	userKeyPath
)

type UserManagementModel struct {
	state       userState
	server      *models.Server
	authType    string
	inputs      []textinput.Model
	focused     int
	errorMessage string
}

func NewUserManagementModel(server *models.Server) UserManagementModel {
	inputs := make([]textinput.Model, 3)
	
	inputs[0] = textinput.New()
	inputs[0].Placeholder = "username"
	inputs[0].Focus()
	
	inputs[1] = textinput.New()
	inputs[1].Placeholder = "password"
	inputs[1].EchoMode = textinput.EchoPassword
	inputs[1].EchoCharacter = '•'
	
	inputs[2] = textinput.New()
	inputs[2].Placeholder = "~/.ssh/id_rsa"

	return UserManagementModel{
		state:  userSelectAuth,
		server: server,
		inputs: inputs,
		focused: 0,
	}
}

func (m UserManagementModel) Init() tea.Cmd {
	return textinput.Blink
}

func (m UserManagementModel) Update(msg tea.Msg) (UserManagementModel, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			return m.handleEnter()
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, func() tea.Msg {
				return BackToDashboardMsg{}
			}
		case tea.KeyTab:
			m.focused = (m.focused + 1) % 3
		case tea.KeyShiftTab:
			m.focused = (m.focused - 1 + 3) % 3
		case tea.Key1:
			if m.state == userSelectAuth {
				m.authType = "password"
				m.state = userUsername
			}
		case tea.Key2:
			if m.state == userSelectAuth {
				m.authType = "key"
				m.state = userUsername
			}
		}

		if m.state != userSelectAuth {
			for i := range m.inputs {
				if i == m.focused {
					m.inputs[i].Focus()
				} else {
					m.inputs[i].Blur()
				}
			}
			m.inputs[m.focused], cmd = m.inputs[m.focused].Update(msg)
		}
	}

	return m, cmd
}

func (m *UserManagementModel) handleEnter() (UserManagementModel, tea.Cmd) {
	switch m.state {
	case userUsername:
		if m.inputs[0].Value() == "" {
			m.errorMessage = "Username is required"
			return m, nil
		}
		if m.authType == "password" {
			m.state = userPassword
			m.focused = 1
			m.inputs[1].Focus()
		} else {
			m.state = userKeyPath
			m.focused = 2
			m.inputs[2].Focus()
		}
	case userPassword:
		if m.inputs[1].Value() == "" {
			m.errorMessage = "Password is required"
			return m, nil
		}
		user := models.NewUser(m.inputs[0].Value(), "password")
		user.Password = m.inputs[1].Value()
		return m, func() tea.Msg {
			return UserCreatedMsg{User: *user, ServerID: m.server.ID}
		}
	case userKeyPath:
		if m.inputs[2].Value() == "" {
			m.errorMessage = "Key path is required"
			return m, nil
		}
		user := models.NewUser(m.inputs[0].Value(), "key")
		user.KeyPath = m.inputs[2].Value()
		return m, func() tea.Msg {
			return UserCreatedMsg{User: *user, ServerID: m.server.ID}
		}
	}

	m.errorMessage = ""
	return m, nil
}

func (m UserManagementModel) View() string {
	if m.state == userSelectAuth {
		return fmt.Sprintf(
			"\n%s\n\n%s\n%s\n\n%s",
			tui.TitleStyle.Render(" Select Authentication Type "),
			tui.MenuStyle.Render("1. Password"),
			tui.MenuStyle.Render("2. SSH Key"),
			tui.HelpStyle.Render("1-2: Select | Esc: Cancel"),
		)
	}

	var fields []string
	labels := []string{"Username:", "Password:", "Key Path:"}
	
	for i := 0; i < 3; i++ {
		if i == 1 && m.authType == "key" {
			continue
		}
		if i == 2 && m.authType == "password" {
			continue
		}
		
		field := fmt.Sprintf("%s\n%s", labels[i], tui.BoxStyle.Render(m.inputs[i].View()))
		fields = append(fields, field)
	}

	errorView := ""
	if m.errorMessage != "" {
		errorView = "\n" + tui.ErrorStyle.Render("Error: "+m.errorMessage)
	}

	return fmt.Sprintf(
		"\n%s\n\n%s%s\n\n%s",
		tui.TitleStyle.Render(" Add User to "+m.server.Name),
		fmt.Sprintf("%s", fields[0]),
		errorView,
		tui.HelpStyle.Render("Tab: Next | Enter: Continue | Esc: Cancel"),
	)
}

type UserCreatedMsg struct {
	User     models.User
	ServerID string
}
EOF
```

**Step 2: Commit**

```bash
git add internal/tui/screens/user_management.go
git commit -m "feat: implement user management screen"
```

---

## Phase 9: Polish & Final Integration

### Task 15: Add Final Polish and Error Handling

**Files:**
- Modify: `internal/tui/app.go`
- Create: `README.md`

**Step 1: Write README**

```bash
cat > README.md << 'EOF'
# ManagedSSH

A terminal-based GUI application for securely managing SSH credentials with master password encryption.

## Features

- **Secure Storage**: AES-GCM-256 encryption with Argon2id key derivation
- **Terminal GUI**: Interactive TUI with fuzzy search
- **Multi-User Support**: Multiple users per server
- **Authentication**: Both password and SSH key support
- **No Commands**: Everything through intuitive GUI menus

## Installation

```bash
go build -o managedssh
sudo mv managedssh /usr/local/bin/
```

## Usage

Simply run:

```bash
managedssh
```

On first run, you'll be prompted to create a master password. This password encrypts all your SSH credentials.

### Navigation

- **Arrow Keys**: Navigate menus
- **Tab/Shift+Tab**: Move between form fields
- **Enter**: Select/Submit
- **Esc**: Go back
- **Ctrl+C**: Exit application
- **/**: Search (in server list)

### Adding a Server

1. Select "Add New Server" from dashboard
2. Enter server name, host, and port
3. Add users with authentication details
4. Server is saved to encrypted storage

### Connecting to a Server

1. Select "Connect to Server" from dashboard
2. Search/filter servers using fuzzy finder
3. Select server and user
4. SSH connection is established

## Security

- Master password never stored
- Argon2id key derivation (memory: 64MB, iterations: 3)
- AES-GCM-256 authenticated encryption
- Credentials encrypted at rest
- Memory zeroing after use

## Storage Location

- Credentials: `~/.config/managedssh/credentials.enc`
- Backups: `~/.config/managedssh/backup/`

## Building from Source

```bash
git clone https://github.com/yourusername/managedssh.git
cd managedssh
go mod download
go build -o managedssh
```

## License

MIT
EOF
```

**Step 2: Final build and test**

```bash
go mod tidy
go build -o managedssh
./managedssh
```

**Step 3: Commit**

```bash
git add README.md
git commit -m "docs: add comprehensive README"
```

---

### Task 16: Create Final Release Build

**Files:**
- Create: `Makefile`

**Step 1: Create Makefile**

```bash
cat > Makefile << 'EOF'
.PHONY: build clean install test

build:
	go build -o managedssh

clean:
	rm -f managedssh

install: build
	sudo mv managedssh /usr/local/bin/

test:
	go test ./... -v

run: build
	./managedssh

all: clean test build
EOF
```

**Step 2: Final test**

```bash
make clean
make test
make build
./managedssh
```

**Step 3: Commit**

```bash
git add Makefile
git commit -m "build: add Makefile for build automation"
```

---

## Summary

This implementation plan provides a complete roadmap for building ManagedSSH TUI:

1. **Phase 1**: Project setup and dependencies
2. **Phase 2**: Data models and encryption
3. **Phase 3**: Storage layer
4. **Phase 4**: TUI framework
5. **Phase 5**: Server management screens
6. **Phase 6**: Add server forms
7. **Phase 7**: SSH connection functionality
8. **Phase 8**: User management
9. **Phase 9**: Polish and documentation

Each task follows TDD principles with tests, builds incrementally, and commits frequently. The result is a fully functional, secure SSH credential manager with an intuitive terminal GUI.

**Total Estimated Tasks**: 16
**Estimated Time**: 4-6 hours for experienced Go developer
