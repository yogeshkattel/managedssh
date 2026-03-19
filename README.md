# ManagedSSH

A terminal UI application for managing and connecting to SSH hosts, built in Go. Stores host configurations locally with passwords encrypted at rest using a master key.

## Features

- **Interactive TUI** — Full-screen terminal interface with keyboard-driven navigation
- **Master key protection** — All sensitive data is encrypted with a master password using Argon2id + AES-256-GCM
- **Host management** — Add, edit, delete, and search SSH hosts
- **Encrypted password storage** — Passwords are encrypted before touching disk and only decrypted in memory at connection time
- **SSH key and password auth** — Supports SSH agent, local key files (`id_ed25519`, `id_rsa`, `id_ecdsa`), password, and keyboard-interactive authentication
- **Full PTY sessions** — Connects with `xterm-256color`, forwards terminal resize signals

## Installation

### From source

```bash
git clone https://github.com/managedssh/managedssh.git
cd managedssh
go build -o managedssh .
```

Move the binary somewhere in your `$PATH`:

```bash
sudo mv managedssh /usr/local/bin/
```

### Requirements

- Go 1.21+ (uses built-in `min`/`max`)
- Linux or macOS (SIGWINCH handling requires Unix)

## Usage

```bash
managedssh
```

### First run

On first launch you'll be prompted to create a **master key** (minimum 8 characters). This key derives a 256-bit encryption key that protects all stored passwords. You'll need to enter it every time you start the application.

### Dashboard

After unlocking, you land on the main dashboard:

```
⚡ ManagedSSH
🔍 Type to filter hosts...

╭ Hosts ──────────────────────╮ ╭ Server Details ─────────────╮
│ ▸ prod-web    192.168.1.10  │ │   Alias      prod-web       │
│   staging     10.0.0.5      │ │   Host       192.168.1.10   │
│   db-master   172.16.0.1    │ │   User       root           │
│                             │ │   Port       22             │
│                             │ │   Auth       SSH Key        │
╰─────────────────────────────╯ ├ Commands ───────────────────┤
                                │   a add         e edit      │
                                │   d delete      ⏎ connect   │
                                │   / search      q quit      │
                                ╰─────────────────────────────╯
```

### Keybindings

| Key | Action |
|-----|--------|
| `j` / `↓` | Move cursor down |
| `k` / `↑` | Move cursor up |
| `a` | Add new host |
| `e` | Edit selected host |
| `d` | Delete selected host (press twice to confirm) |
| `Enter` | SSH into selected host |
| `/` | Focus search — live-filters by alias, hostname, or user |
| `Esc` | Clear search filter |
| `q` | Quit |

### Host form

| Key | Action |
|-----|--------|
| `Tab` / `↓` | Next field |
| `Shift+Tab` / `↑` | Previous field |
| `Space` | Toggle auth method (on Auth Method field) |
| `Enter` | Save |
| `Esc` | Cancel |

## Architecture

```
managedssh/
├── main.go                         Entry point
├── cmd/
│   └── root.go                     Cobra CLI root command
├── internal/
│   ├── vault/
│   │   └── vault.go                Master key, key derivation, encryption
│   ├── host/
│   │   └── store.go                Host model, JSON persistence, CRUD
│   ├── sshclient/
│   │   └── client.go               SSH connection, PTY, auth methods
│   └── tui/
│       ├── app.go                  Bubble Tea model, phase routing, auth screens
│       ├── dashboard.go            Host list, details panel, commands panel
│       ├── hostform.go             Add/edit form with auth toggle
│       └── styles.go               Lip Gloss color palette and styles
├── go.mod
└── go.sum
```

### Internal packages

| Package | Responsibility |
|---------|---------------|
| `vault` | Master key lifecycle. Derives a 256-bit key from the password via **Argon2id** (64 MB memory, 4 threads). Encrypts/decrypts arbitrary data with **AES-256-GCM**. Stores only a salt and encrypted verifier token — never the password. |
| `host` | `Host` struct and `Store` for CRUD operations. Persists hosts as JSON at `~/.config/managedssh/hosts.json`. Passwords are stored as encrypted byte blobs (opaque to the store). |
| `sshclient` | Implements Bubble Tea's `ExecCommand` interface for seamless terminal handoff. Negotiates auth, requests a PTY, starts a shell, and forwards `SIGWINCH` for terminal resize. |
| `tui` | All UI logic. A single Bubble Tea `model` with phase-based routing (`setup → unlock → dashboard → hostform`). Each phase has its own `update` and `view` methods split across files. |

### Security model

```
Master password
      │
      ▼
 Argon2id (salt, 64MB, 4 threads)
      │
      ▼
 256-bit derived key (held in memory only)
      │
      ├──▶ Encrypts vault verifier (AES-256-GCM) → ~/.config/managedssh/vault.json
      │
      └──▶ Encrypts host passwords (AES-256-GCM) → ~/.config/managedssh/hosts.json
```

- The master password is **never stored**. Only a random salt and an encrypted verifier token are written to disk.
- On unlock, the password is re-derived through Argon2id and tested by decrypting the verifier. A mismatch means wrong password.
- Each host password is independently encrypted with a unique random nonce. The nonce is prepended to the ciphertext.
- The derived key exists **only in process memory** for the duration of the session.
- All config files are written with `0600` permissions. The config directory uses `0700`.

### SSH authentication

When connecting, auth methods are tried in this order:

1. **Password** + **keyboard-interactive** (if the host has a stored password)
2. **SSH agent** (`SSH_AUTH_SOCK`)
3. **Key files** (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa`)

The SSH session runs with a full `xterm-256color` PTY. Terminal resize signals (`SIGWINCH`) are forwarded to the remote session in real time.

### Data storage

All data lives under `~/.config/managedssh/`:

| File | Contents | Sensitive |
|------|----------|-----------|
| `vault.json` | Argon2 salt, AES-GCM nonce, encrypted verifier | Salt is public; verifier is encrypted |
| `hosts.json` | Host entries (alias, hostname, user, port, auth type, encrypted password blob) | Passwords are encrypted; metadata is plaintext |

### Tech stack

| Library | Purpose |
|---------|---------|
| [Bubble Tea](https://github.com/charmbracelet/bubbletea) | Terminal UI framework (Elm architecture) |
| [Lip Gloss](https://github.com/charmbracelet/lipgloss) | TUI styling — colors, borders, layout |
| [Bubbles](https://github.com/charmbracelet/bubbles) | Text input components |
| [Cobra](https://github.com/spf13/cobra) | CLI command framework |
| [x/crypto](https://pkg.go.dev/golang.org/x/crypto) | Argon2id key derivation, SSH client, SSH agent |
| [x/term](https://pkg.go.dev/golang.org/x/term) | Raw terminal mode, terminal size detection |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a Pull Request

## License

MIT
