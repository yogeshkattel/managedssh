package tui

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/managedssh/managedssh/internal/audit"
	"github.com/managedssh/managedssh/internal/host"
	"github.com/managedssh/managedssh/internal/vault"
)

type phase int

const (
	phaseProfileSelect phase = iota
	phaseProfileCreate
	phaseSetup
	phaseSetupConfirm
	phaseUnlock
	phaseDashboard
	phaseHostForm
	phaseUserSelect
	phaseChangeKey
	phaseChangeKeyConfirm
)

// Auto-lock: lock after 5 minutes of inactivity.
const autoLockTimeout = 5 * time.Minute

// sshDoneMsg is sent after an SSH session completes (or fails).
type sshDoneMsg struct{ err error }

// tickMsg for auto-lock timer.
type tickMsg time.Time

type model struct {
	phase    phase
	width    int
	height   int
	quitting bool

	encKey []byte

	// Auth (setup + unlock) — password stored as []byte so it can be zeroed.
	input    textinput.Model
	password []byte
	err      string

	// Auto-lock
	lastActivity time.Time

	// Audit log
	auditLog *audit.Log

	// Profile selection
	profiles      []string
	profileCursor int
	profileName   string

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
	formInputs   []textinput.Model
	formFocus    int
	formEditing  string
	formErr      string
	formAuthType string

	// Change key
	changeKeyOld []byte
	changeKeyNew []byte
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func cloneHosts(src []host.Host) []host.Host {
	out := make([]host.Host, len(src))
	for i, h := range src {
		out[i] = h
		out[i].Users = append([]string(nil), h.Users...)
		out[i].Tags = append([]string(nil), h.Tags...)
		out[i].EncPassword = append([]byte(nil), h.EncPassword...)
	}
	return out
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

func initialModel() (model, error) {
	m := model{
		lastActivity: time.Now(),
	}

	if vault.ActiveProfile() != "" {
		return m.resolveAuthPhase()
	}

	// Check if multiple profiles exist.
	profiles, err := vault.ListProfiles()
	if err != nil {
		return model{}, err
	}

	if len(profiles) > 1 {
		m.phase = phaseProfileSelect
		m.profiles = profiles
		m.profileCursor = 0
		return m, nil
	}

	// Single or no profile — use default.
	if len(profiles) == 1 {
		vault.SetProfile(profiles[0])
	}

	return m.resolveAuthPhase()
}

func (m model) resolveAuthPhase() (model, error) {
	if err := vault.RecoverPendingRotation(); err != nil {
		return model{}, err
	}

	exists, err := vault.Exists()
	if err != nil {
		return model{}, err
	}

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
	auditLog, err := audit.NewLog(dir)
	if err != nil {
		return m, err
	}
	m.store = store
	m.auditLog = auditLog
	m.search = newSearchInput()
	m.searchFocused = false
	m.hostCursor = 0
	m.confirmDelete = false
	m.connErr = ""
	m.filtered = store.Filter("")
	m.phase = phaseDashboard
	m.lastActivity = time.Now()
	return m, nil
}

func (m model) refreshFiltered() model {
	m.filtered = m.store.Filter(m.search.Value())
	if m.hostCursor >= len(m.filtered) {
		m.hostCursor = max(0, len(m.filtered)-1)
	}
	return m
}

// tickCmd returns a command that fires a tick after 30 seconds.
func tickCmd() tea.Cmd {
	return tea.Tick(30*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// ------------------------------------------------------------------
// Tea interface
// ------------------------------------------------------------------

func (m model) Init() tea.Cmd {
	return tea.Batch(textinput.Blink, tickCmd())
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case tea.KeyMsg:
		m.lastActivity = time.Now()
		if msg.String() == "ctrl+c" {
			vault.ZeroKey(m.encKey)
			m.quitting = true
			return m, tea.Quit
		}
	case tickMsg:
		// Auto-lock check: if unlocked and idle too long, lock.
		if m.phase == phaseDashboard || m.phase == phaseHostForm || m.phase == phaseUserSelect {
			if time.Since(m.lastActivity) >= autoLockTimeout {
				// Lock: wipe key, go back to unlock.
				vault.ZeroKey(m.encKey)
				m.encKey = nil
				m.store = nil
				m.filtered = nil
				m.phase = phaseUnlock
				m.input = newPasswordInput("Session locked — enter master key...")
				m.err = "Session auto-locked due to inactivity"
				return m, tea.Batch(textinput.Blink, tickCmd())
			}
		}
		return m, tickCmd()
	case sshDoneMsg:
		m.connErr = ""
		if msg.err != nil {
			m.connErr = msg.err.Error()
		}
		m.lastActivity = time.Now()
		return m, nil
	}

	switch m.phase {
	case phaseProfileSelect:
		return m.updateProfileSelect(msg)
	case phaseProfileCreate:
		return m.updateProfileCreate(msg)
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
	case phaseChangeKey:
		return m.updateChangeKey(msg)
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
	case phaseProfileSelect:
		content = m.viewProfileSelect()
	case phaseProfileCreate:
		content = m.viewProfileCreate()
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
	case phaseChangeKey:
		content = m.viewChangeKey()
	case phaseChangeKeyConfirm:
		content = m.viewChangeKeyConfirm()
	}

	if m.width > 0 {
		content = lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
	}
	return content
}

// ------------------------------------------------------------------
// Profile selection
// ------------------------------------------------------------------

func (m model) updateProfileSelect(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	switch key.String() {
	case "j", "down":
		if m.profileCursor < len(m.profiles)-1 {
			m.profileCursor++
		}
	case "k", "up":
		if m.profileCursor > 0 {
			m.profileCursor--
		}
	case "enter":
		selected := m.profiles[m.profileCursor]
		vault.SetProfile(selected)
		nm, err := m.resolveAuthPhase()
		if err != nil {
			m.err = err.Error()
			return m, nil
		}
		return nm, textinput.Blink
	case "n":
		m.phase = phaseProfileCreate
		m.input = textinput.New()
		m.input.Placeholder = "e.g. work, staging, client-a"
		m.input.CharLimit = 64
		m.input.Width = 40
		m.input.Focus()
		m.err = ""
		m.profileName = ""
		return m, textinput.Blink
	}
	return m, nil
}

func (m model) viewProfileSelect() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("👤 Select Profile") + "\n")
	b.WriteString(subtitleStyle.Render("Choose a profile to unlock.") + "\n\n")

	for i, p := range m.profiles {
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(text)
		if i == m.profileCursor {
			prefix = "▸ "
			style = lipgloss.NewStyle().Foreground(highlight).Bold(true)
		}
		label := p
		if p == "default" {
			label = "default (main)"
		}
		b.WriteString(style.Render(prefix+label) + "\n")
	}

	b.WriteString("\n")
	b.WriteString(statusBarStyle.Render("↑↓ navigate • enter select • n new profile • ctrl+c quit"))
	return boxStyle.Render(b.String())
}

func (m model) updateProfileCreate(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.phase = phaseProfileSelect
			m.err = ""
			m.profileName = ""
			return m, nil
		case "enter":
			name := strings.TrimSpace(m.input.Value())
			if err := vault.ValidateProfileName(name); err != nil {
				m.err = err.Error()
				return m, nil
			}
			for _, existing := range m.profiles {
				if strings.EqualFold(existing, name) {
					m.err = "Profile already exists"
					return m, nil
				}
			}
			vault.SetProfile(name)
			m.profileName = name
			m.phase = phaseSetup
			m.input = newPasswordInput("Choose a master key...")
			m.err = ""
			return m, textinput.Blink
		}
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) viewProfileCreate() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("👤 New Profile") + "\n")
	b.WriteString(subtitleStyle.Render("Create a separate vault and host list.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("Profile Name") + "\n")
	b.WriteString(m.input.View() + "\n\n")
	if m.err != "" {
		b.WriteString(errorStyle.Render("✗ "+m.err) + "\n\n")
	}
	b.WriteString(hintStyle.Render("Avoid path-like names such as ../prod or nested paths") + "\n")
	b.WriteString(statusBarStyle.Render("enter continue • esc back • ctrl+c quit"))
	return boxStyle.Render(b.String())
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
		// Enforce password strength: must contain uppercase, lowercase, and digit.
		hasUpper, hasLower, hasDigit := false, false, false
		for _, c := range val {
			switch {
			case c >= 'A' && c <= 'Z':
				hasUpper = true
			case c >= 'a' && c <= 'z':
				hasLower = true
			case c >= '0' && c <= '9':
				hasDigit = true
			}
		}
		if !hasUpper || !hasLower || !hasDigit {
			m.err = "Must contain uppercase, lowercase, and a digit"
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
	profile := vault.ActiveProfile()
	if profile == "" {
		profile = "default"
	}
	b.WriteString(titleStyle.Render("🔐 First Time Setup") + "\n")
	b.WriteString(subtitleStyle.Render(fmt.Sprintf("Profile: %s", profile)) + "\n")
	if m.profileName != "" {
		b.WriteString(subtitleStyle.Render("Creating a new isolated profile.") + "\n")
	}
	b.WriteString(subtitleStyle.Render("Choose a master key to protect your data.") + "\n")
	b.WriteString(subtitleStyle.Render("This encrypts all stored passwords and keys.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("Master Key") + "\n")
	b.WriteString(m.input.View() + "\n\n")
	if m.err != "" {
		b.WriteString(errorStyle.Render("✗ "+m.err) + "\n\n")
	}
	b.WriteString(hintStyle.Render("Min 8 chars, must include A-Z, a-z, 0-9") + "\n")
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
			dm.profileName = ""
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
			} else if errors.Is(err, vault.ErrAccountLocked) {
				m.err = err.Error()
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
		dm.profileName = ""
		return dm, nil
	}

	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) viewUnlock() string {
	var b strings.Builder
	profile := vault.ActiveProfile()
	if profile == "" {
		profile = "default"
	}
	b.WriteString(titleStyle.Render("🔑 ManagedSSH") + "\n")
	b.WriteString(subtitleStyle.Render(fmt.Sprintf("Profile: %s", profile)) + "\n")
	b.WriteString(subtitleStyle.Render("Enter your master key to unlock.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("Master Key") + "\n")
	b.WriteString(m.input.View() + "\n\n")
	if m.err != "" {
		b.WriteString(errorStyle.Render("✗ "+m.err) + "\n\n")
	}
	b.WriteString(statusBarStyle.Render("enter unlock • ctrl+c quit"))
	return boxStyle.Render(b.String())
}

// ------------------------------------------------------------------
// Change master key
// ------------------------------------------------------------------

func (m model) startChangeKey() model {
	m.phase = phaseChangeKey
	m.input = newPasswordInput("New master key...")
	m.err = ""
	m.changeKeyOld = nil
	m.changeKeyNew = nil
	return m
}

func (m model) updateChangeKey(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.phase = phaseDashboard
			m.err = ""
			return m, nil
		case "enter":
			val := m.input.Value()
			if len(val) < 8 {
				m.err = "Master key must be at least 8 characters"
				return m, nil
			}
			hasUpper, hasLower, hasDigit := false, false, false
			for _, c := range val {
				switch {
				case c >= 'A' && c <= 'Z':
					hasUpper = true
				case c >= 'a' && c <= 'z':
					hasLower = true
				case c >= '0' && c <= '9':
					hasDigit = true
				}
			}
			if !hasUpper || !hasLower || !hasDigit {
				m.err = "Must contain uppercase, lowercase, and a digit"
				return m, nil
			}
			m.changeKeyNew = []byte(val)
			m.phase = phaseChangeKeyConfirm
			m.input = newPasswordInput("Confirm new master key...")
			m.err = ""
			return m, textinput.Blink
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) viewChangeKey() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("🔄 Change Master Key") + "\n")
	b.WriteString(subtitleStyle.Render("Enter your new master key.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("New Master Key") + "\n")
	b.WriteString(m.input.View() + "\n\n")
	if m.err != "" {
		b.WriteString(errorStyle.Render("✗ "+m.err) + "\n\n")
	}
	b.WriteString(hintStyle.Render("Min 8 chars, must include A-Z, a-z, 0-9") + "\n")
	b.WriteString(statusBarStyle.Render("enter confirm • esc cancel"))
	return boxStyle.Render(b.String())
}

func (m model) updateChangeKeyConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			zeroBytes(m.changeKeyNew)
			m.changeKeyNew = nil
			m.phase = phaseDashboard
			m.err = ""
			return m, nil
		case "enter":
			val := m.input.Value()
			if val != string(m.changeKeyNew) {
				m.err = "Keys do not match"
				m.input.Reset()
				return m, nil
			}
			newKey, metaData, err := vault.BuildPasswordMetadata(val)
			if err != nil {
				m.err = "Failed to change key: " + err.Error()
				return m, nil
			}

			rotatedHosts := cloneHosts(m.store.Hosts)
			for i, h := range rotatedHosts {
				if len(h.EncPassword) > 0 {
					reenc, err := vault.ReEncrypt(m.encKey, newKey, h.EncPassword)
					if err != nil {
						m.err = "Failed to re-encrypt host passwords"
						vault.ZeroKey(newKey)
						return m, nil
					}
					rotatedHosts[i].EncPassword = reenc
				}
			}

			oldHosts := cloneHosts(m.store.Hosts)
			if err := vault.CreateRotationBackup(); err != nil {
				m.err = "Failed to prepare password change: " + err.Error()
				vault.ZeroKey(newKey)
				return m, nil
			}

			m.store.Hosts = rotatedHosts
			if err := m.store.Save(); err != nil {
				m.store.Hosts = oldHosts
				_ = vault.ClearRotationBackup()
				m.err = "Failed to save hosts: " + err.Error()
				vault.ZeroKey(newKey)
				return m, nil
			}

			if err := vault.WriteMetadata(metaData); err != nil {
				m.store.Hosts = oldHosts
				_ = m.store.Save()
				_ = vault.RecoverPendingRotation()
				m.err = "Failed to change key: " + err.Error()
				vault.ZeroKey(newKey)
				return m, nil
			}
			if err := vault.ClearRotationBackup(); err != nil {
				m.store.Hosts = oldHosts
				_ = m.store.Save()
				_ = vault.RecoverPendingRotation()
				m.err = "Failed to finalize password change: " + err.Error()
				vault.ZeroKey(newKey)
				return m, nil
			}

			vault.ZeroKey(m.encKey)
			m.encKey = newKey
			zeroBytes(m.changeKeyNew)
			m.changeKeyNew = nil
			m.phase = phaseDashboard
			m.connErr = "Master key changed successfully"
			m.err = ""
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) viewChangeKeyConfirm() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("🔄 Confirm New Key") + "\n")
	b.WriteString(subtitleStyle.Render("Type your new master key again.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("Confirm New Key") + "\n")
	b.WriteString(m.input.View() + "\n\n")
	if m.err != "" {
		b.WriteString(errorStyle.Render("✗ "+m.err) + "\n\n")
	}
	b.WriteString(statusBarStyle.Render("enter confirm • esc cancel"))
	return boxStyle.Render(b.String())
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
