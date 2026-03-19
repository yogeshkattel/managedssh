# Security Vulnerabilities — Audit & Fixes

Tracked vulnerabilities found during security review, with fix status.

## CRITICAL

| ID | Issue | File | Status |
|----|-------|------|--------|
| C1 | `InsecureIgnoreHostKey` — no host key verification, enables MITM | `sshclient/client.go:68` | FIXED |
| C2 | Non-atomic file writes — crash can corrupt vault or host data | `host/store.go`, `vault/vault.go` | FIXED |

## HIGH

| ID | Issue | File | Status |
|----|-------|------|--------|
| H1 | `argonTime=1` below OWASP minimum — weak brute-force resistance | `vault/vault.go:17` | FIXED |
| H2 | Encryption key never zeroed from memory on exit | `tui/app.go:34` | FIXED |
| H3 | Master password held as immutable Go `string` — cannot be wiped | `tui/app.go:38` | FIXED |
| H4 | Decrypted host passwords linger in heap as `string` | `tui/dashboard.go`, `sshclient/client.go` | FIXED |

## MEDIUM

| ID | Issue | File | Status |
|----|-------|------|--------|
| M1 | Keyboard-interactive answers ALL challenges with password | `sshclient/client.go:41-48` | FIXED |
| M2 | SIGWINCH goroutine leaks after SSH session ends | `sshclient/client.go:120-129` | FIXED |
| M3 | Store CRUD errors silently discarded | `tui/dashboard.go`, `tui/hostform.go` | FIXED |

## LOW

| ID | Issue | File | Status |
|----|-------|------|--------|
| L1 | Host ID only 32-bit entropy, `rand.Read` error suppressed | `host/store.go:27-30` | FIXED |
| L2 | `TrimSpace` on passwords strips intentional whitespace | `tui/hostform.go`, `tui/app.go` | FIXED |
| L3 | AES-GCM without AAD — ciphertexts transplantable between roles | `vault/vault.go:77` | FIXED |
| L4 | Private key files loaded without permission checks | `sshclient/client.go:146-165` | FIXED |
