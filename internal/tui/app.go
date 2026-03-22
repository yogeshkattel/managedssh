package tui

import (
	"errors"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/crypto/ssh"

	"github.com/managedssh/managedssh/internal/host"
	"github.com/managedssh/managedssh/internal/sshclient"
	"github.com/managedssh/managedssh/internal/vault"
)

type phase int

const (
	phaseSetup phase = iota
	phaseSetupConfirm
	phaseUnlock
	phaseDashboard
	phaseHostForm
	phaseUserSelect
	phaseHostVerifying
	phaseHostTrustConfirm
	phaseKeyPassphrasePrompt
	phaseChangeKeyInit
	phaseChangeKeyNew
	phaseChangeKeyConfirm
)

type sshDoneMsg struct{ err error }
type hostVerifyDoneMsg struct{ err error }
type hostTrustDoneMsg struct{ err error }
type saveKeyPassDoneMsg struct{ err error }
type dashboardTrustDoneMsg struct{ err error }

type formUserConfig struct {
	Username            string
	AuthType            string
	Password            string
	ExistingEncPassword []byte
	KeyValue            string
	ExistingKeyPath     string
	ExistingEncKey      []byte
	ExistingEncKeyPass  []byte
}

type model struct {
	phase         phase
	previousPhase phase
	width         int
	height        int
	quitting      bool

	encKey []byte

	// Auth (setup + unlock) — password stored as []byte so it can be zeroed.
	input    textinput.Model
	password []byte
	err      string

	// Dashboard
	store         *host.Store
	filtered      []host.Host
	hostCursor    int
	search        textinput.Model
	searchFocused bool
	confirmDelete bool
	connErr       string
	userCursor    int
	selectedHost  host.Host

	// Host form
	formInputs             []textinput.Model
	formFocus              int
	formEditing            string
	formErr                string
	formDefaultUser        string
	formUserConfigs        []formUserConfig
	formUserCursor         int
	formPathSuggestions    []string
	formPathSuggestIndex   int
	pendingHost            host.Host
	pendingEditID          string
	pendingTrust           *sshclient.UnknownHostError
	connectHost            host.Host
	connectUser            string
	connectResolved        host.ResolvedAuth
	connectPassphraseInput textinput.Model
	pendingKeyPassSave     bool
	pendingKeyPassphrase   []byte
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func newPasswordInput(placeholder string) textinput.Model {
	ti := textinput.New()
	ti.Placeholder = placeholder
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.Focus()
	ti.CharLimit = 128
	ti.Width = 40
	return ti
}

func newSearchInput() textinput.Model {
	ti := textinput.New()
	ti.Placeholder = "Type to filter hosts..."
	ti.CharLimit = 64
	ti.Width = 30
	return ti
}

func newKeyPassphraseInput() textinput.Model {
	ti := textinput.New()
	ti.Placeholder = "Enter SSH key passphrase..."
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '•'
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 40
	return ti
}

func initialModel() (model, error) {
	exists, err := vault.Exists()
	if err != nil {
		return model{}, err
	}

	m := model{}
	if exists {
		m.phase = phaseUnlock
		m.input = newPasswordInput("Enter master key...")
	} else {
		m.phase = phaseSetup
		m.input = newPasswordInput("Choose a master key...")
	}
	return m, nil
}

func (m model) initDashboard() (model, error) {
	dir, err := vault.Dir()
	if err != nil {
		return m, err
	}
	store, err := host.NewStore(dir)
	if err != nil {
		return m, err
	}
	m.store = store
	m.search = newSearchInput()
	m.searchFocused = false
	m.hostCursor = 0
	m.confirmDelete = false
	m.connErr = ""
	m.filtered = store.Filter("")
	m.phase = phaseDashboard
	return m, nil
}

func (m model) refreshFiltered() model {
	m.filtered = m.store.Filter(m.search.Value())
	if m.hostCursor >= len(m.filtered) {
		m.hostCursor = max(0, len(m.filtered)-1)
	}
	return m
}

// ------------------------------------------------------------------
// Tea interface
// ------------------------------------------------------------------

func (m model) Init() tea.Cmd {
	return textinput.Blink
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			vault.ZeroKey(m.encKey)
			m.quitting = true
			return m, tea.Quit
		}
	case sshDoneMsg:
		m.connErr = ""
		if msg.err != nil {
			// Ignore normal exit-status errors (user typed "exit" / logout).
			var exitErr *ssh.ExitError
			if errors.As(msg.err, &exitErr) {
				m.pendingKeyPassSave = false
				zeroBytes(m.pendingKeyPassphrase)
				m.pendingKeyPassphrase = nil
				return m, nil
			}
			var unknown *sshclient.UnknownHostError
			if errors.As(msg.err, &unknown) {
				m.previousPhase = m.phase
				m.phase = phaseHostTrustConfirm
				m.pendingTrust = unknown
				return m, nil
			}
			if m.phase == phaseDashboard && m.pendingKeyPassSave {
				m.phase = phaseKeyPassphrasePrompt
				m.connectPassphraseInput = newKeyPassphraseInput()
			}
			m.connErr = formatAuthErr(msg.err)
			m.pendingKeyPassSave = false
			zeroBytes(m.pendingKeyPassphrase)
			m.pendingKeyPassphrase = nil
			return m, nil
		}
		if m.pendingKeyPassSave && len(m.pendingKeyPassphrase) > 0 {
			return m, saveKeyPassphraseCmd(m.store, m.connectHost.ID, m.connectUser, m.encKey, m.pendingKeyPassphrase)
		}
		return m, nil
	case hostVerifyDoneMsg:
		return m.handleHostVerifyDone(msg)
	case hostTrustDoneMsg:
		return m.handleHostTrustDone(msg)
	case saveKeyPassDoneMsg:
		if msg.err != nil {
			m.connErr = "Connected, but failed to save key passphrase: " + msg.err.Error()
		}
		m.pendingKeyPassSave = false
		zeroBytes(m.pendingKeyPassphrase)
		m.pendingKeyPassphrase = nil
		return m, nil
	case dashboardTrustDoneMsg:
		if msg.err != nil {
			m.phase = phaseDashboard
			m.connErr = "Failed to trust host key: " + msg.err.Error()
			return m, nil
		}
		return m.connectSSHWithResolved(m.connectHost, m.connectUser, m.connectResolved, m.pendingKeyPassphrase, m.pendingKeyPassSave)
	}

	switch m.phase {
	case phaseSetup:
		return m.updateSetup(msg)
	case phaseSetupConfirm:
		return m.updateSetupConfirm(msg)
	case phaseUnlock:
		return m.updateUnlock(msg)
	case phaseDashboard:
		return m.updateDashboard(msg)
	case phaseHostForm:
		return m.updateHostForm(msg)
	case phaseUserSelect:
		return m.updateUserSelect(msg)
	case phaseHostVerifying:
		return m.updateHostVerifying(msg)
	case phaseHostTrustConfirm:
		return m.updateHostTrustConfirm(msg)
	case phaseKeyPassphrasePrompt:
		return m.updateKeyPassphrasePrompt(msg)
	case phaseChangeKeyInit:
		return m.updateChangeKeyInit(msg)
	case phaseChangeKeyNew:
		return m.updateChangeKeyNew(msg)
	case phaseChangeKeyConfirm:
		return m.updateChangeKeyConfirm(msg)
	}
	return m, nil
}

func (m model) View() string {
	if m.quitting {
		return ""
	}

	var content string
	switch m.phase {
	case phaseSetup:
		content = m.viewSetup()
	case phaseSetupConfirm:
		content = m.viewSetupConfirm()
	case phaseUnlock:
		content = m.viewUnlock()
	case phaseDashboard:
		return m.viewDashboard()
	case phaseHostForm:
		content = m.viewHostForm()
	case phaseUserSelect:
		content = m.viewUserSelect()
	case phaseHostVerifying:
		content = m.viewHostVerifying()
	case phaseHostTrustConfirm:
		content = m.viewHostTrustConfirm()
	case phaseKeyPassphrasePrompt:
		content = m.viewKeyPassphrasePrompt()
	case phaseChangeKeyInit:
		content = m.viewChangeKeyInit()
	case phaseChangeKeyNew:
		content = m.viewChangeKeyNew()
	case phaseChangeKeyConfirm:
		content = m.viewChangeKeyConfirm()
	}

	if m.width > 0 {
		content = lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
	}
	return content
}

// ------------------------------------------------------------------
// Setup — choose master key
// ------------------------------------------------------------------

func (m model) updateSetup(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok && key.String() == "enter" {
		val := m.input.Value()
		if len(val) < 8 {
			m.err = "Master key must be at least 8 characters"
			return m, nil
		}
		m.password = []byte(val)
		m.err = ""
		m.phase = phaseSetupConfirm
		m.input = newPasswordInput("Confirm master key...")
		return m, textinput.Blink
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) viewSetup() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("🔐 First Time Setup") + "\n")
	b.WriteString(subtitleStyle.Render("Choose a master key to protect your data.") + "\n")
	b.WriteString(subtitleStyle.Render("This encrypts all stored passwords and keys.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("Master Key") + "\n")
	b.WriteString(m.input.View() + "\n\n")
	if m.err != "" {
		b.WriteString(errorStyle.Render("✗ "+m.err) + "\n\n")
	}
	b.WriteString(hintStyle.Render("Minimum 8 characters") + "\n")
	b.WriteString(statusBarStyle.Render("enter confirm • ctrl+c quit"))
	return boxStyle.Render(b.String())
}

// ------------------------------------------------------------------
// Setup — confirm master key
// ------------------------------------------------------------------

func (m model) updateSetupConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.phase = phaseSetup
			zeroBytes(m.password)
			m.password = nil
			m.err = ""
			m.input = newPasswordInput("Choose a master key...")
			return m, textinput.Blink
		case "enter":
			val := m.input.Value()
			if val != string(m.password) {
				m.err = "Keys do not match — try again"
				m.input.Reset()
				return m, nil
			}
			encKey, err := vault.Create(val)
			if err != nil {
				m.err = "Failed to create vault"
				return m, nil
			}
			m.encKey = encKey
			zeroBytes(m.password)
			m.password = nil
			m.err = ""
			dm, derr := m.initDashboard()
			if derr != nil {
				m.err = "Failed to load host store"
				return m, nil
			}
			return dm, nil
		}
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) viewSetupConfirm() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("🔐 Confirm Master Key") + "\n")
	b.WriteString(subtitleStyle.Render("Type your master key again to confirm.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("Confirm Key") + "\n")
	b.WriteString(m.input.View() + "\n\n")
	if m.err != "" {
		b.WriteString(errorStyle.Render("✗ "+m.err) + "\n\n")
	}
	b.WriteString(statusBarStyle.Render("enter confirm • esc go back • ctrl+c quit"))
	return boxStyle.Render(b.String())
}

// ------------------------------------------------------------------
// Unlock — returning user
// ------------------------------------------------------------------

func (m model) updateUnlock(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok && key.String() == "enter" {
		val := m.input.Value()
		encKey, err := vault.Unlock(val)
		if err != nil {
			if errors.Is(err, vault.ErrWrongPassword) {
				m.err = "Incorrect master key"
			} else {
				m.err = "Unlock failed"
			}
			m.input.Reset()
			return m, nil
		}
		m.encKey = encKey
		m.err = ""
		dm, derr := m.initDashboard()
		if derr != nil {
			m.err = "Failed to load host store"
			return m, nil
		}
		return dm, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) viewUnlock() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("🔑 ManagedSSH") + "\n")
	b.WriteString(subtitleStyle.Render("Enter your master key to unlock.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("Master Key") + "\n")
	b.WriteString(m.input.View() + "\n\n")
	if m.err != "" {
		b.WriteString(errorStyle.Render("✗ "+m.err) + "\n\n")
	}
	b.WriteString(statusBarStyle.Render("enter unlock • ctrl+c quit"))
	return boxStyle.Render(b.String())
}

func (m model) updateHostVerifying(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok && key.String() == "ctrl+c" {
		vault.ZeroKey(m.encKey)
		m.quitting = true
		return m, tea.Quit
	}
	return m, nil
}

func (m model) updateHostTrustConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch key.String() {
	case "y", "enter":
		m.formErr = ""
		if m.previousPhase == phaseDashboard {
			return m, func() tea.Msg {
				err := sshclient.TrustHostKey(m.pendingTrust)
				return dashboardTrustDoneMsg{err: err}
			}
		}
		m.phase = phaseHostVerifying
		return m, trustAndVerifyHostCmd(m.pendingHost, m.encKey, m.pendingTrust)
	case "n", "esc":
		m.pendingTrust = nil
		if m.previousPhase == phaseDashboard {
			m.phase = phaseDashboard
			m.connErr = "Host key was not trusted."
			return m, nil
		}
		m.phase = phaseHostForm
		m.formErr = "Host key was not trusted, so the host was not saved"
		return m, nil
	}

	return m, nil
}

func (m model) handleHostVerifyDone(msg hostVerifyDoneMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		var unknown *sshclient.UnknownHostError
		if errors.As(msg.err, &unknown) {
			m.phase = phaseHostTrustConfirm
			m.pendingTrust = unknown
			return m, nil
		}
		m.phase = phaseHostForm
		m.formErr = formatAuthErr(msg.err)
		return m, nil
	}

	if err := m.savePendingHost(); err != nil {
		m.phase = phaseHostForm
		m.formErr = "Failed to save: " + err.Error()
		return m, nil
	}

	m.phase = phaseDashboard
	m.formErr = ""
	m.pendingHost = host.Host{}
	m.pendingEditID = ""
	m.pendingTrust = nil
	m = m.refreshFiltered()
	return m, nil
}

func (m model) handleHostTrustDone(msg hostTrustDoneMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		m.phase = phaseHostForm
		m.formErr = "Failed to trust host key: " + msg.err.Error()
		return m, nil
	}
	return m, verifyHostCmd(m.pendingHost, m.encKey)
}

func (m *model) savePendingHost() error {
	if m.pendingEditID != "" {
		return m.store.Update(m.pendingEditID, m.pendingHost)
	}
	return m.store.Add(m.pendingHost)
}

func verifyHostCmd(h host.Host, encKey []byte) tea.Cmd {
	return func() tea.Msg {
		return hostVerifyDoneMsg{err: verifyHostBeforeSave(h, encKey)}
	}
}

func trustAndVerifyHostCmd(h host.Host, encKey []byte, unknown *sshclient.UnknownHostError) tea.Cmd {
	return func() tea.Msg {
		if err := sshclient.TrustHostKey(unknown); err != nil {
			return hostTrustDoneMsg{err: err}
		}
		return hostTrustDoneMsg{}
	}
}

func verifyHostBeforeSave(h host.Host, encKey []byte) error {
	for _, username := range h.AccountNames() {
		_, resolved, ok := h.ResolveAccount(username)
		if !ok {
			return errors.New("missing account during verification")
		}

		var password []byte
		if resolved.AuthType == "password" && len(resolved.Password) > 0 {
			dec, err := vault.Decrypt(encKey, resolved.Password)
			if err != nil {
				return fmt.Errorf("failed to decrypt password for %s: %w", username, err)
			}
			password = dec
		}

		var keyData []byte
		if resolved.AuthType == "key" && len(resolved.EncKey) > 0 {
			dec, err := vault.Decrypt(encKey, resolved.EncKey)
			if err != nil {
				zeroBytes(password)
				return fmt.Errorf("failed to decrypt SSH key for %s: %w", username, err)
			}
			keyData = dec
		}

		err := sshclient.Verify(sshclient.VerifyConfig{
			Host:     h.Hostname,
			Port:     h.Port,
			User:     username,
			Password: password,
			KeyPath:  resolved.KeyPath,
			KeyData:  keyData,
		})
		zeroBytes(password)
		zeroBytes(keyData)
		if err != nil {
			var unknown *sshclient.UnknownHostError
			if errors.As(err, &unknown) {
				return unknown
			}
			var needPass *sshclient.KeyPassphraseRequiredError
			if errors.As(err, &needPass) {
				continue
			}
			return fmt.Errorf("verification failed for %s: %w", username, err)
		}
	}
	return nil
}

func (m model) viewHostVerifying() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Verifying Host") + "\n\n")
	b.WriteString(subtitleStyle.Render("Checking host key and credentials before saving.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("Host") + "\n")
	b.WriteString(detailValueStyle.Render(m.pendingHost.Alias+" • "+m.pendingHost.Hostname) + "\n\n")
	b.WriteString(hintStyle.Render("Please wait...") + "\n")
	return boxStyle.Render(b.String())
}

func (m model) viewHostTrustConfirm() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("Trust Host Key") + "\n\n")
	b.WriteString(subtitleStyle.Render("This server is not in known_hosts yet.") + "\n\n")
	if m.pendingTrust != nil {
		b.WriteString(inputLabelStyle.Render("Host") + "\n")
		b.WriteString(detailValueStyle.Render(m.pendingTrust.Host) + "\n\n")
		b.WriteString(inputLabelStyle.Render("Fingerprint") + "\n")
		b.WriteString(detailValueStyle.Render(m.pendingTrust.Fingerprint) + "\n\n")
		b.WriteString(inputLabelStyle.Render("Key Type") + "\n")
		b.WriteString(detailValueStyle.Render(m.pendingTrust.KeyType) + "\n\n")
	}
	b.WriteString(hintStyle.Render("Press y to trust and continue, or n to cancel save.") + "\n")
	b.WriteString(statusBarStyle.Render("y trust • n cancel • enter trust • esc cancel"))
	return boxStyle.Render(b.String())
}

func (m model) updateKeyPassphrasePrompt(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.phase = phaseDashboard
			m.connErr = "SSH key passphrase entry cancelled"
			return m, nil
		case "enter":
			passphrase := []byte(m.connectPassphraseInput.Value())
			if len(passphrase) == 0 {
				m.connErr = "SSH key passphrase is required"
				return m, nil
			}
			zeroBytes(m.pendingKeyPassphrase)
			m.pendingKeyPassphrase = append([]byte(nil), passphrase...)
			m.pendingKeyPassSave = true
			return m.connectSSHWithResolved(m.connectHost, m.connectUser, m.connectResolved, passphrase, true)
		}
	}

	var cmd tea.Cmd
	m.connectPassphraseInput, cmd = m.connectPassphraseInput.Update(msg)
	return m, cmd
}

func (m model) viewKeyPassphrasePrompt() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("SSH Key Passphrase") + "\n\n")
	b.WriteString(subtitleStyle.Render("This SSH key is encrypted and needs its passphrase.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("User") + "\n")
	b.WriteString(detailValueStyle.Render(m.connectUser+" @ "+m.connectHost.Hostname) + "\n\n")
	b.WriteString(inputLabelStyle.Render("Passphrase") + "\n")
	b.WriteString(m.connectPassphraseInput.View() + "\n\n")
	if m.connErr != "" {
		b.WriteString(errorStyle.Render("✗ "+m.connErr) + "\n\n")
	}
	b.WriteString(statusBarStyle.Render("enter connect • esc cancel"))
	return boxStyle.Render(b.String())
}

func saveKeyPassphraseCmd(store *host.Store, hostID, username string, encKey []byte, passphrase []byte) tea.Cmd {
	return func() tea.Msg {
		return saveKeyPassDoneMsg{err: saveKeyPassphrase(store, hostID, username, encKey, passphrase)}
	}
}

func saveKeyPassphrase(store *host.Store, hostID, username string, encKey []byte, passphrase []byte) error {
	enc, err := vault.Encrypt(encKey, passphrase)
	if err != nil {
		return err
	}
	for i := range store.Hosts {
		if store.Hosts[i].ID != hostID {
			continue
		}
		account, _, ok := store.Hosts[i].ResolveAccount(username)
		if !ok {
			return fmt.Errorf("account not found")
		}
		if account.UseDefault {
			store.Hosts[i].DefaultEncKeyPass = enc
			return store.Save()
		}
		for j := range store.Hosts[i].Accounts {
			if store.Hosts[i].Accounts[j].Username == username {
				store.Hosts[i].Accounts[j].EncKeyPass = enc
				return store.Save()
			}
		}
	}
	return fmt.Errorf("host not found")
}

// ------------------------------------------------------------------
// Entry point
// ------------------------------------------------------------------

func Start() error {
	m, err := initialModel()
	if err != nil {
		return err
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	result, err := p.Run()
	if fm, ok := result.(model); ok {
		vault.ZeroKey(fm.encKey)
	}
	return err
}

func formatAuthErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if strings.Contains(s, "unable to authenticate") || strings.Contains(s, "sign failed") || strings.Contains(s, "agent:") {
		s += "\n  Tip: If you suspect a stale SSH/GPG agent conflict, run `ssh-add -D` and `gpgconf --kill gpg-agent`."
	}
	return s
}
