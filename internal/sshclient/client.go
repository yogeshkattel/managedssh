package sshclient

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
	"golang.org/x/term"
)

// Session implements bubbletea.ExecCommand so it can be handed
// the terminal via tea.Exec while the SSH session is active.
type Session struct {
	Host     string
	Port     int
	User     string
	Password []byte

	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (s *Session) SetStdin(r io.Reader)  { s.stdin = r }
func (s *Session) SetStdout(w io.Writer) { s.stdout = w }
func (s *Session) SetStderr(w io.Writer) { s.stderr = w }

func (s *Session) Run() error {
	defer s.zeroPassword()

	var authMethods []ssh.AuthMethod

	if len(s.Password) > 0 {
		pw := string(s.Password)
		authMethods = append(authMethods, ssh.Password(pw))
		authMethods = append(authMethods, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				if len(questions) == 1 && !echos[0] {
					answers[0] = pw
				}
				return answers, nil
			},
		))
	}

	if agentAuth, conn := dialAgent(); agentAuth != nil {
		defer conn.Close()
		authMethods = append(authMethods, agentAuth)
	}

	if signers := loadKeyFiles(); len(signers) > 0 {
		authMethods = append(authMethods, ssh.PublicKeys(signers...))
	}

	if len(authMethods) == 0 {
		return fmt.Errorf("no authentication method available (no password, agent, or key files found)")
	}

	hostKeyCallback, err := buildHostKeyCallback()
	if err != nil {
		return fmt.Errorf("known_hosts setup failed: %w", err)
	}

	config := &ssh.ClientConfig{
		User:            s.User,
		Auth:            authMethods,
		HostKeyCallback: hostKeyCallback,
		Timeout:         10 * time.Second,
	}

	addr := net.JoinHostPort(s.Host, strconv.Itoa(s.Port))
	fmt.Fprintf(s.stdout, "Connecting to %s@%s ...\r\n", s.User, addr)

	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return fmt.Errorf("connection failed: %w", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("session failed: %w", err)
	}
	defer session.Close()

	fd := int(os.Stdin.Fd())
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return fmt.Errorf("terminal setup failed: %w", err)
	}
	defer term.Restore(fd, oldState)

	w, h, _ := term.GetSize(fd)
	if w == 0 {
		w = 80
	}
	if h == 0 {
		h = 24
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}
	if err := session.RequestPty("xterm-256color", h, w, modes); err != nil {
		return fmt.Errorf("PTY request failed: %w", err)
	}

	session.Stdin = s.stdin
	session.Stdout = s.stdout
	session.Stderr = s.stderr

	if err := session.Shell(); err != nil {
		return fmt.Errorf("shell failed: %w", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			if nw, nh, err := term.GetSize(fd); err == nil {
				_ = session.WindowChange(nh, nw)
			}
		}
	}()
	defer func() {
		signal.Stop(sigCh)
		close(sigCh)
	}()

	return session.Wait()
}

func (s *Session) zeroPassword() {
	for i := range s.Password {
		s.Password[i] = 0
	}
	s.Password = nil
}

// buildHostKeyCallback loads ~/.ssh/known_hosts for host key verification.
// If the file doesn't exist yet it is created so future connections are
// verified (trust-on-first-use will be handled by the ssh library's error
// reporting — the user sees a clear error and can add the key manually).
func buildHostKeyCallback() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	khPath := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(khPath); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(khPath), 0700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(khPath, nil, 0600); err != nil {
			return nil, err
		}
	}
	return knownhosts.New(khPath)
}

func dialAgent() (ssh.AuthMethod, net.Conn) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil
	}
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil
	}
	return ssh.PublicKeysCallback(agent.NewClient(conn).Signers), conn
}

func loadKeyFiles() []ssh.Signer {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	names := []string{"id_ed25519", "id_rsa", "id_ecdsa"}
	var signers []ssh.Signer
	for _, name := range names {
		p := filepath.Join(home, ".ssh", name)

		info, err := os.Stat(p)
		if err != nil {
			continue
		}
		if perm := info.Mode().Perm(); perm&0077 != 0 {
			continue
		}

		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			continue
		}
		signers = append(signers, signer)
	}
	return signers
}
