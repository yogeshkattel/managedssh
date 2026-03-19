package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/managedssh/managedssh/internal/host"
	"github.com/managedssh/managedssh/internal/vault"
)

// Form field indices.
const (
	fAlias    = 0
	fHostname = 1
	fUser     = 2
	fPort     = 3
	fAuth     = 4 // not a textinput — toggle handled separately
	fPassword = 5 // maps to formInputs[4]
)

// formInputIdx returns the textinput slice index for a given focus
// position, or -1 for the auth toggle which has no textinput.
func formInputIdx(focus int) int {
	if focus >= 0 && focus <= 3 {
		return focus
	}
	if focus == fPassword {
		return 4
	}
	return -1
}

func newHostFormInputs(alias, hostname, user string, port int) []textinput.Model {
	inputs := make([]textinput.Model, 5)

	inputs[0] = textinput.New()
	inputs[0].Placeholder = "e.g. prod-web"
	inputs[0].CharLimit = 64
	inputs[0].Width = 36
	inputs[0].Focus()

	inputs[1] = textinput.New()
	inputs[1].Placeholder = "e.g. 192.168.1.10 or example.com"
	inputs[1].CharLimit = 256
	inputs[1].Width = 36

	inputs[2] = textinput.New()
	inputs[2].Placeholder = "e.g. root"
	inputs[2].CharLimit = 64
	inputs[2].Width = 36

	inputs[3] = textinput.New()
	inputs[3].Placeholder = "22"
	inputs[3].CharLimit = 5
	inputs[3].Width = 10

	inputs[4] = textinput.New()
	inputs[4].Placeholder = "Enter password (optional)"
	inputs[4].EchoMode = textinput.EchoPassword
	inputs[4].EchoCharacter = '•'
	inputs[4].CharLimit = 128
	inputs[4].Width = 36

	inputs[0].SetValue(alias)
	inputs[1].SetValue(hostname)
	inputs[2].SetValue(user)
	if port > 0 {
		inputs[3].SetValue(fmt.Sprintf("%d", port))
	}

	return inputs
}

func (m model) startHostForm(editID string) (model, tea.Cmd) {
	m.phase = phaseHostForm
	m.formEditing = editID
	m.formFocus = 0
	m.formErr = ""
	m.formAuthType = "key"

	var alias, hostname, user string
	var port int
	if editID != "" {
		for _, h := range m.store.Hosts {
			if h.ID == editID {
				alias = h.Alias
				hostname = h.Hostname
				user = h.User
				port = h.Port
				if h.AuthType != "" {
					m.formAuthType = h.AuthType
				}
				break
			}
		}
	}

	m.formInputs = newHostFormInputs(alias, hostname, user, port)
	return m, textinput.Blink
}

// ------------------------------------------------------------------
// Update
// ------------------------------------------------------------------

func (m model) updateHostForm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.phase = phaseDashboard
			m = m.refreshFiltered()
			return m, nil

		case "tab", "down":
			return m.cycleFormFocus(1)

		case "shift+tab", "up":
			return m.cycleFormFocus(-1)

		case " ":
			if m.formFocus == fAuth {
				if m.formAuthType == "key" {
					m.formAuthType = "password"
				} else {
					m.formAuthType = "key"
				}
				return m, nil
			}

		case "enter":
			return m.submitHostForm()
		}
	}

	if idx := formInputIdx(m.formFocus); idx >= 0 {
		var cmd tea.Cmd
		m.formInputs[idx], cmd = m.formInputs[idx].Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m model) cycleFormFocus(dir int) (tea.Model, tea.Cmd) {
	maxFocus := fAuth
	if m.formAuthType == "password" {
		maxFocus = fPassword
	}

	if idx := formInputIdx(m.formFocus); idx >= 0 {
		m.formInputs[idx].Blur()
	}

	m.formFocus += dir
	if m.formFocus > maxFocus {
		m.formFocus = 0
	} else if m.formFocus < 0 {
		m.formFocus = maxFocus
	}

	if idx := formInputIdx(m.formFocus); idx >= 0 {
		m.formInputs[idx].Focus()
		return m, textinput.Blink
	}
	return m, nil
}

func (m model) submitHostForm() (tea.Model, tea.Cmd) {
	alias := strings.TrimSpace(m.formInputs[0].Value())
	hostname := strings.TrimSpace(m.formInputs[1].Value())
	user := strings.TrimSpace(m.formInputs[2].Value())
	portStr := strings.TrimSpace(m.formInputs[3].Value())
	pwd := m.formInputs[4].Value()

	if alias == "" {
		m.formErr = "Alias is required"
		return m, nil
	}
	if hostname == "" {
		m.formErr = "Hostname is required"
		return m, nil
	}
	if user == "" {
		m.formErr = "User is required"
		return m, nil
	}

	port := 22
	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			m.formErr = "Port must be 1–65535"
			return m, nil
		}
		port = p
	}

	h := host.Host{
		Alias:    alias,
		Hostname: hostname,
		User:     user,
		Port:     port,
		AuthType: m.formAuthType,
	}

	if m.formAuthType == "password" {
		if pwd != "" {
			enc, err := vault.Encrypt(m.encKey, []byte(pwd))
			if err != nil {
				m.formErr = "Failed to encrypt password: " + err.Error()
				return m, nil
			}
			h.EncPassword = enc
		} else if m.formEditing != "" {
			for _, existing := range m.store.Hosts {
				if existing.ID == m.formEditing {
					h.EncPassword = existing.EncPassword
					break
				}
			}
		}
	}

	if m.formEditing != "" {
		if err := m.store.Update(m.formEditing, h); err != nil {
			m.formErr = "Failed to save: " + err.Error()
			return m, nil
		}
	} else {
		if err := m.store.Add(h); err != nil {
			m.formErr = "Failed to save: " + err.Error()
			return m, nil
		}
	}

	m.phase = phaseDashboard
	m.formErr = ""
	m = m.refreshFiltered()
	return m, nil
}

// ------------------------------------------------------------------
// View
// ------------------------------------------------------------------

func (m model) viewHostForm() string {
	title := "Add Host"
	if m.formEditing != "" {
		title = "Edit Host"
	}

	var b strings.Builder
	b.WriteString(titleStyle.Render("📝 "+title) + "\n\n")

	renderField := func(focus int, label string, idx int) {
		focused := m.formFocus == focus
		lbl := inputLabelStyle.Render(label)
		if focused {
			lbl = lipgloss.NewStyle().Foreground(highlight).Bold(true).Render("▸ " + label)
		}
		b.WriteString(lbl + "\n")
		b.WriteString(m.formInputs[idx].View() + "\n\n")
	}

	renderField(fAlias, "Alias", 0)
	renderField(fHostname, "Hostname", 1)
	renderField(fUser, "User", 2)
	renderField(fPort, "Port", 3)

	// Auth type toggle
	{
		focused := m.formFocus == fAuth
		lbl := inputLabelStyle.Render("Auth Method")
		if focused {
			lbl = lipgloss.NewStyle().Foreground(highlight).Bold(true).Render("▸ Auth Method")
		}
		b.WriteString(lbl + "\n")

		keyLbl := "○ SSH Key"
		pwLbl := "○ Password"
		keyS := lipgloss.NewStyle().Foreground(text)
		pwS := lipgloss.NewStyle().Foreground(text)
		if m.formAuthType == "key" {
			keyLbl = "● SSH Key"
			keyS = lipgloss.NewStyle().Foreground(highlight).Bold(true)
		} else {
			pwLbl = "● Password"
			pwS = lipgloss.NewStyle().Foreground(highlight).Bold(true)
		}

		toggle := "  " + keyS.Render(keyLbl) + "    " + pwS.Render(pwLbl)
		if focused {
			toggle += hintStyle.Render("  (space to toggle)")
		}
		b.WriteString(toggle + "\n\n")
	}

	if m.formAuthType == "password" {
		renderField(fPassword, "Password", 4)
		if m.formEditing != "" {
			b.WriteString(hintStyle.Render("  Leave empty to keep current password") + "\n\n")
		}
	}

	if m.formErr != "" {
		b.WriteString(errorStyle.Render("✗ "+m.formErr) + "\n\n")
	}

	b.WriteString(statusBarStyle.Render("tab/↑↓ navigate • space toggle auth • enter save • esc cancel"))
	return boxStyle.Render(b.String())
}
