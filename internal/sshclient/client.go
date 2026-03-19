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
	"golang.org/x/term"
)

// Session implements bubbletea.ExecCommand so it can be handed
// the terminal via tea.Exec while the SSH session is active.
type Session struct {
	Host     string
	Port     int
	User     string
	Password string

	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
}

func (s *Session) SetStdin(r io.Reader)  { s.stdin = r }
func (s *Session) SetStdout(w io.Writer) { s.stdout = w }
func (s *Session) SetStderr(w io.Writer) { s.stderr = w }

func (s *Session) Run() error {
	var authMethods []ssh.AuthMethod

	if s.Password != "" {
		authMethods = append(authMethods, ssh.Password(s.Password))
		authMethods = append(authMethods, ssh.KeyboardInteractive(
			func(_, _ string, questions []string, _ []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range questions {
					answers[i] = s.Password
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

	config := &ssh.ClientConfig{
		User:            s.User,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
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

	// Forward terminal resize signals to the remote PTY.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for range sigCh {
			if nw, nh, err := term.GetSize(fd); err == nil {
				_ = session.WindowChange(nh, nw)
			}
		}
	}()
	defer signal.Stop(sigCh)

	return session.Wait()
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
		data, err := os.ReadFile(filepath.Join(home, ".ssh", name))
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
