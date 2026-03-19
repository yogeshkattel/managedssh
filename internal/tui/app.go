package tui

import (
	"errors"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/managedssh/managedssh/internal/host"
	"github.com/managedssh/managedssh/internal/vault"
)

type phase int

const (
	phaseSetup phase = iota
	phaseSetupConfirm
	phaseUnlock
	phaseDashboard
	phaseHostForm
)

// sshDoneMsg is sent after an SSH session completes (or fails).
type sshDoneMsg struct{ err error }

type model struct {
	phase    phase
	width    int
	height   int
	quitting bool

	encKey []byte

	// Auth (setup + unlock)
	input    textinput.Model
	password string
	err      string

	// Dashboard
	store         *host.Store
	filtered      []host.Host
	hostCursor    int
	search        textinput.Model
	searchFocused bool
	confirmDelete bool
	connErr       string

	// Host form
	formInputs   []textinput.Model
	formFocus    int
	formEditing  string
	formErr      string
	formAuthType string
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
			m.quitting = true
			return m, tea.Quit
		}
	case sshDoneMsg:
		m.connErr = ""
		if msg.err != nil {
			m.connErr = msg.err.Error()
		}
		return m, nil
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
		val := strings.TrimSpace(m.input.Value())
		if len(val) < 8 {
			m.err = "Master key must be at least 8 characters"
			return m, nil
		}
		m.password = val
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
			m.password = ""
			m.err = ""
			m.input = newPasswordInput("Choose a master key...")
			return m, textinput.Blink
		case "enter":
			val := strings.TrimSpace(m.input.Value())
			if val != m.password {
				m.err = "Keys do not match — try again"
				m.input.Reset()
				return m, nil
			}
			encKey, err := vault.Create(val)
			if err != nil {
				m.err = "Failed to create vault: " + err.Error()
				return m, nil
			}
			m.encKey = encKey
			m.password = ""
			m.err = ""
			dm, derr := m.initDashboard()
			if derr != nil {
				m.err = derr.Error()
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
		val := strings.TrimSpace(m.input.Value())
		encKey, err := vault.Unlock(val)
		if err != nil {
			if errors.Is(err, vault.ErrWrongPassword) {
				m.err = "Incorrect master key"
			} else {
				m.err = "Error: " + err.Error()
			}
			m.input.Reset()
			return m, nil
		}
		m.encKey = encKey
		m.err = ""
		dm, derr := m.initDashboard()
		if derr != nil {
			m.err = derr.Error()
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

// ------------------------------------------------------------------
// Entry point
// ------------------------------------------------------------------

func Start() error {
	m, err := initialModel()
	if err != nil {
		return err
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err = p.Run()
	return err
}
