# ManagedSSH

A terminal UI application for managing and connecting to SSH hosts, built in Go. Stores host configurations locally with passwords encrypted at rest using a master key.

## Features

- **Interactive TUI** — Full-screen terminal interface with keyboard-driven navigation
- **Multiple profiles** — Separate vaults and host lists per profile, selectable at launch or via `--profile`
- **Master key protection** — All sensitive data is encrypted with a master password using Argon2id + AES-256-GCM
- **Host management** — Add, edit, delete, group, tag, and search SSH hosts
- **Multi-user hosts** — Store multiple SSH users per host and choose one at connect time
- **Session controls** — Manual lock, automatic idle lock, and in-app master key rotation
- **Encrypted password storage** — Passwords are encrypted before touching disk and only decrypted in memory at connection time
- **SSH key and password auth** — Supports SSH agent, local key files (`id_ed25519`, `id_rsa`, `id_ecdsa`), password, and keyboard-interactive authentication
- **Connection tuning** — Per-host connection timeout from 1 to 300 seconds
- **RBAC controls** — Profile-scoped `admin`, `operator`, and `viewer` roles for TUI and CLI actions
- **Health monitoring** — Run TCP reachability checks across hosts from the dashboard or CLI
- **SSH key management** — Generate and inspect local SSH keys from the CLI
- **Compliance export** — Export audit history as JSON or CSV reports
- **Session recording** — Record terminal session traffic to per-session log files
- **Analytics** — Summarize connection success rates, hot hosts, users, and recent failures
- **Audit log** — Appends connection and host-management events to a local JSONL log
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

### CLI commands

```bash
managedssh [--profile <name>]
managedssh profiles
managedssh version
managedssh role get
managedssh role set [admin|operator|viewer]
managedssh health
managedssh audit export --format json --output report.json
managedssh audit stats
managedssh keys list
managedssh keys generate managedssh_prod --comment "ops@example.com"
managedssh sessions
```

| Command | Purpose |
|---------|---------|
| `managedssh` | Start the TUI using auto-detected profile selection |
| `managedssh --profile work` | Start directly in a specific profile |
| `managedssh profiles` | List available local profiles |
| `managedssh version` | Print the app version |
| `managedssh role get` | Show the current profile role |
| `managedssh role set ...` | Change the current profile role |
| `managedssh health` | Run host reachability checks for the current profile |
| `managedssh audit export ...` | Export audit history for compliance/reporting |
| `managedssh audit stats` | Show analytics summary from audit history |
| `managedssh keys list` | List local SSH key pairs in `~/.ssh/` |
| `managedssh keys generate ...` | Generate a new Ed25519 SSH key pair |
| `managedssh sessions` | List recorded SSH session logs |

### First run

On first launch you'll be prompted to create a **master key**. This key derives a 256-bit encryption key that protects all stored passwords. You'll need to enter it every time you start the application.

Master key requirements:

- Minimum 8 characters
- Must include at least one uppercase letter
- Must include at least one lowercase letter
- Must include at least one digit

After five failed unlock attempts, the selected profile is temporarily locked for five minutes.

### Profiles

ManagedSSH supports isolated profiles. Each profile has its own:

- `vault.json`
- `hosts.json`
- `audit.jsonl`

Startup behavior:

1. If no profile exists yet, the app starts first-time setup.
2. If exactly one profile exists, it is selected automatically.
3. If multiple profiles exist, the app shows a profile picker.

Profile picker keys:

| Key | Action |
|-----|--------|
| `j` / `↓` | Move down |
| `k` / `↑` | Move up |
| `Enter` | Open selected profile |
| `n` | Create a new profile |
| `Ctrl+C` | Quit |

Profile names must be simple labels, not paths. Values such as `../prod` or nested paths are rejected in both the TUI and `--profile`.

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
                                │   / search      h health    │
                                │   s stats       l lock      │
                                │   a add         e edit      │
                                │   d delete      ⏎ connect   │
                                │   c change key  q quit      │
                                ╰─────────────────────────────╯
```

Search matches:

- Alias
- Hostname
- User list
- Group
- Tags

### Dashboard keys

| Key | Action |
|-----|--------|
| `j` / `↓` | Move cursor down |
| `k` / `↑` | Move cursor up |
| `a` | Add new host |
| `e` | Edit selected host |
| `d` | Delete selected host (press twice to confirm) |
| `Enter` | SSH into selected host, or choose a user first if the host has multiple users |
| `/` | Focus search — live-filters as you type |
| `Esc` | Clear search filter |
| `c` | Change the master key |
| `h` | Run health checks for visible hosts |
| `l` | Lock the current session immediately |
| `q` | Quit |
| `s` | Show connection analytics summary |

When a host has multiple users, ManagedSSH opens a user picker before connecting.

User picker keys:

| Key | Action |
|-----|--------|
| `j` / `↓` | Move down |
| `k` / `↑` | Move up |
| `Enter` | Connect with selected user |
| `Esc` | Return to dashboard |

### Host form

Fields:

- Alias
- Hostname
- Users, comma-separated
- Port
- Group
- Tags, comma-separated
- Timeout in seconds
- Auth method: `SSH Key` or `Password`
- Password, when password auth is selected

| Key | Action |
|-----|--------|
| `Tab` / `↓` | Next field |
| `Shift+Tab` / `↑` | Previous field |
| `Space` | Toggle auth method (on Auth Method field) |
| `Enter` | Save |
| `Esc` | Cancel |

Validation rules:

- Alias is required
- Hostname is required
- At least one user is required
- Port must be `1-65535`
- Timeout must be `1-300` seconds when set

Password handling:

- Passwords are optional even when password auth is selected
- Existing passwords are preserved during edit if the password field is left empty
- Passwords are decrypted only in memory right before connection

### Locking and key rotation

- The session auto-locks after 5 minutes of inactivity
- `l` locks the session immediately
- `c` rotates the master key and re-encrypts stored host passwords
- Interrupted master-key rotation is recovered automatically on next start

### Enterprise controls

Roles:

- `admin`: full access, including export, keys, sessions, and role management
- `operator`: connect, view hosts, run health checks, view analytics, and lock
- `viewer`: browse hosts only

Enterprise CLI workflows:

- `managedssh health` checks all hosts in the selected profile
- `managedssh audit export --format json|csv --output file` writes audit exports with `0600` file permissions
- `managedssh audit stats` shows connection analytics
- `managedssh keys generate <name>` creates a new Ed25519 key pair under `~/.ssh/`
- `managedssh sessions` lists recorded session logs for the profile

RBAC enforcement:

- `role set` requires an `admin` profile role
- `health` requires a role that can run health checks
- `audit export` requires `admin`
- `audit stats` requires a role that can view analytics
- `keys` requires `admin`
- `sessions` requires `admin`

Session recording:

- SSH sessions are recorded under the profile `sessions/` directory
- Recordings include live terminal traffic plus session start/end metadata
- Filenames are sanitized to stay inside the profile recording directory

### SSH connection behavior

When connecting, auth methods are tried in this order:

1. **Password** + **keyboard-interactive** (if the host has a stored password)
2. **SSH agent** (`SSH_AUTH_SOCK`)
3. **Key files** (`~/.ssh/id_ed25519`, `~/.ssh/id_rsa`, `~/.ssh/id_ecdsa`)

The SSH session runs with a full `xterm-256color` PTY. Terminal resize signals (`SIGWINCH`) are forwarded to the remote session in real time. Host keys are verified against `~/.ssh/known_hosts`.

## Architecture

```
managedssh/
├── main.go                         Entry point
├── cmd/
│   └── root.go                     Cobra CLI root command
├── internal/
│   ├── vault/
│   │   └── vault.go                Master key, key derivation, encryption
│   ├── audit/
│   │   └── audit.go                JSONL audit logging
│   ├── analytics/
│   │   └── analytics.go            Connection summaries and trends
│   ├── compliance/
│   │   └── compliance.go           Audit/compliance export helpers
│   ├── health/
│   │   └── health.go               Concurrent TCP health checks
│   ├── host/
│   │   └── store.go                Host model, JSON persistence, CRUD
│   ├── keymgr/
│   │   └── keymgr.go               Local SSH key generation and listing
│   ├── rbac/
│   │   └── rbac.go                 Profile-scoped role enforcement
│   ├── session/
│   │   └── recorder.go             Session recording and listing
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
| `vault` | Master key lifecycle. Derives a 256-bit key from the password via **Argon2id** (128 MB memory, 4 threads). Encrypts/decrypts arbitrary data with **AES-256-GCM**. Stores only a salt and encrypted verifier token — never the password. |
| `audit` | Appends structured JSON-lines audit events for connections and host-management actions. |
| `analytics` | Builds connection summaries such as success rates, most-used hosts, and recent failures. |
| `compliance` | Formats audit events as JSON and CSV compliance reports. |
| `health` | Performs concurrent TCP reachability checks for stored hosts. |
| `host` | `Host` struct and `Store` for CRUD operations. Persists hosts as JSON at `~/.config/managedssh/hosts.json`. Passwords are stored as encrypted byte blobs (opaque to the store). |
| `keymgr` | Lists and generates local Ed25519 SSH key pairs with safe filename validation. |
| `rbac` | Persists profile role policy and checks permissions for TUI/CLI actions. |
| `session` | Records and lists SSH session logs for audit/compliance workflows. |
| `sshclient` | Implements Bubble Tea's `ExecCommand` interface for seamless terminal handoff. Negotiates auth, requests a PTY, starts a shell, and forwards `SIGWINCH` for terminal resize. |
| `tui` | All UI logic. A single Bubble Tea `model` with phase-based routing (`profile select → setup/unlock → dashboard → hostform/user select/change key`) plus RBAC-aware health and analytics actions. |

### Security model

```
Master password
      │
      ▼
 Argon2id (salt, 128MB, 4 threads)
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
- Master-key rotation writes a recovery file first so an interrupted re-encryption can be rolled back safely on next launch.

### Data storage

All data lives under `~/.config/managedssh/`.

For the default profile, files are written directly there. Named profiles are stored under `~/.config/managedssh/<profile>/`.

| File | Contents | Sensitive |
|------|----------|-----------|
| `vault.json` | Argon2 salt, AES-GCM nonce, encrypted verifier | Salt is public; verifier is encrypted |
| `hosts.json` | Host entries (alias, hostname, user, port, auth type, encrypted password blob) | Passwords are encrypted; metadata is plaintext |
| `audit.jsonl` | JSON-lines audit events for host changes and SSH connections | Operational metadata |
| `rbac.json` | Persisted role policy for the profile | Operational metadata |
| `rotation.json` | Temporary rollback file used during master-key rotation | Contains previous vault/host state until rotation finishes |
| `lockout.json` | Temporary failed-attempt counter for a locked profile | Operational metadata |
| `sessions/` | Recorded SSH terminal sessions for the profile | Contains session traffic and metadata |

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
