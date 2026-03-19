package tui

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/managedssh/managedssh/internal/audit"
	"github.com/managedssh/managedssh/internal/host"
	"github.com/managedssh/managedssh/internal/vault"
)

// Form field indices.
const (
	fAlias    = 0
	fHostname = 1
	fUser     = 2
	fPort     = 3
	fGroup    = 4
	fTags     = 5
	fTimeout  = 6
	fAuth     = 7 // not a textinput — toggle handled separately
	fPassword = 8 // maps to formInputs[7]
)

// formInputIdx returns the textinput slice index for a given focus
// position, or -1 for the auth toggle which has no textinput.
func formInputIdx(focus int) int {
	switch {
	case focus >= 0 && focus <= 6:
		return focus
	case focus == fPassword:
		return 7
	default:
		return -1
	}
}

func newHostFormInputs(alias, hostname, user string, port int, group, tags string, timeout int) []textinput.Model {
	inputs := make([]textinput.Model, 8)

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
	inputs[2].Placeholder = "e.g. root, ubuntu, deploy"
	inputs[2].CharLimit = 256
	inputs[2].Width = 36

	inputs[3] = textinput.New()
	inputs[3].Placeholder = "22"
	inputs[3].CharLimit = 5
	inputs[3].Width = 10

	inputs[4] = textinput.New()
	inputs[4].Placeholder = "e.g. production, staging"
	inputs[4].CharLimit = 64
	inputs[4].Width = 36

	inputs[5] = textinput.New()
	inputs[5].Placeholder = "e.g. web, database, critical"
	inputs[5].CharLimit = 256
	inputs[5].Width = 36

	inputs[6] = textinput.New()
	inputs[6].Placeholder = "10 (seconds, default)"
	inputs[6].CharLimit = 5
	inputs[6].Width = 10

	inputs[7] = textinput.New()
	inputs[7].Placeholder = "Enter password (optional)"
	inputs[7].EchoMode = textinput.EchoPassword
	inputs[7].EchoCharacter = '•'
	inputs[7].CharLimit = 128
	inputs[7].Width = 36

	inputs[0].SetValue(alias)
	inputs[1].SetValue(hostname)
	inputs[2].SetValue(user)
	if port > 0 {
		inputs[3].SetValue(fmt.Sprintf("%d", port))
	}
	inputs[4].SetValue(group)
	inputs[5].SetValue(tags)
	if timeout > 0 {
		inputs[6].SetValue(fmt.Sprintf("%d", timeout))
	}

	return inputs
}

func (m model) startHostForm(editID string) (model, tea.Cmd) {
	m.phase = phaseHostForm
	m.formEditing = editID
	m.formFocus = 0
	m.formErr = ""
	m.formAuthType = "key"

	var alias, hostname, users, group, tags string
	var port, timeout int
	if editID != "" {
		for _, h := range m.store.Hosts {
			if h.ID == editID {
				alias = h.Alias
				hostname = h.Hostname
				users = strings.Join(h.UserList(), ", ")
				port = h.Port
				group = h.Group
				tags = strings.Join(h.Tags, ", ")
				timeout = h.ConnTimeout
				if h.AuthType != "" {
					m.formAuthType = h.AuthType
				}
				break
			}
		}
	}

	m.formInputs = newHostFormInputs(alias, hostname, users, port, group, tags, timeout)
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
	users := parseUsers(m.formInputs[2].Value())
	portStr := strings.TrimSpace(m.formInputs[3].Value())
	group := strings.TrimSpace(m.formInputs[4].Value())
	tagsRaw := m.formInputs[5].Value()
	timeoutStr := strings.TrimSpace(m.formInputs[6].Value())
	pwd := m.formInputs[7].Value()

	if alias == "" {
		m.formErr = "Alias is required"
		return m, nil
	}
	if hostname == "" {
		m.formErr = "Hostname is required"
		return m, nil
	}
	if len(users) == 0 {
		m.formErr = "At least one user is required"
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

	var connTimeout int
	if timeoutStr != "" {
		t, err := strconv.Atoi(timeoutStr)
		if err != nil || t < 1 || t > 300 {
			m.formErr = "Timeout must be 1–300 seconds"
			return m, nil
		}
		connTimeout = t
	}

	tags := parseTags(tagsRaw)

	h := host.Host{
		Alias:       alias,
		Hostname:    hostname,
		Users:       users,
		Port:        port,
		AuthType:    m.formAuthType,
		Group:       group,
		Tags:        tags,
		ConnTimeout: connTimeout,
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

	action := "host_added"
	if m.formEditing != "" {
		action = "host_updated"
		// Preserve created_at from existing host.
		for _, existing := range m.store.Hosts {
			if existing.ID == m.formEditing {
				h.CreatedAt = existing.CreatedAt
				h.LastConnectedAt = existing.LastConnectedAt
				break
			}
		}
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

	m.logAudit(audit.Event{
		Type:      action,
		HostAlias: alias,
		Hostname:  hostname,
		Success:   true,
	})

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
	renderField(fUser, "Users", 2)
	renderField(fPort, "Port", 3)
	renderField(fGroup, "Group", 4)
	renderField(fTags, "Tags", 5)
	renderField(fTimeout, "Timeout (s)", 6)

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
		renderField(fPassword, "Password", 7)
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

func parseUsers(raw string) []string {
	parts := strings.Split(raw, ",")
	users := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		user := strings.TrimSpace(part)
		if user == "" {
			continue
		}
		if _, ok := seen[user]; ok {
			continue
		}
		seen[user] = struct{}{}
		users = append(users, user)
	}
	return users
}

func parseTags(raw string) []string {
	parts := strings.Split(raw, ",")
	tags := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		tag := strings.TrimSpace(part)
		if tag == "" {
			continue
		}
		if _, ok := seen[tag]; ok {
			continue
		}
		seen[tag] = struct{}{}
		tags = append(tags, tag)
	}
	return tags
}
