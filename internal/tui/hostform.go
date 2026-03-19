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
	fAlias = iota
	fHostname
	fUsers
	fPort
	fDefaultAuth
	fDefaultPassword
	fSelectedUser
	fSelectedUserAuth
	fSelectedUserPassword
)

func formInputIdx(focus int) int {
	switch focus {
	case fAlias:
		return 0
	case fHostname:
		return 1
	case fUsers:
		return 2
	case fPort:
		return 3
	case fDefaultPassword:
		return 4
	case fSelectedUserPassword:
		return 5
	default:
		return -1
	}
}

func newHostFormInputs(alias, hostname, users string, port int) []textinput.Model {
	inputs := make([]textinput.Model, 6)

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
	inputs[4].Placeholder = "Default password"
	inputs[4].EchoMode = textinput.EchoPassword
	inputs[4].EchoCharacter = '•'
	inputs[4].CharLimit = 128
	inputs[4].Width = 36

	inputs[5] = textinput.New()
	inputs[5].Placeholder = "Override password"
	inputs[5].EchoMode = textinput.EchoPassword
	inputs[5].EchoCharacter = '•'
	inputs[5].CharLimit = 128
	inputs[5].Width = 36

	inputs[0].SetValue(alias)
	inputs[1].SetValue(hostname)
	inputs[2].SetValue(users)
	if port > 0 {
		inputs[3].SetValue(fmt.Sprintf("%d", port))
	}

	return inputs
}

func (m model) startHostForm(editID string) (model, tea.Cmd) {
	m.phase = phaseHostForm
	m.formEditing = editID
	m.formFocus = fAlias
	m.formErr = ""
	m.formDefaultAuth = "key"
	m.formDefaultEncPassword = nil
	m.formUserConfigs = nil
	m.formUserCursor = 0

	var alias, hostname, users string
	var port int
	if editID != "" {
		for _, h := range m.store.Hosts {
			if h.ID != editID {
				continue
			}
			alias = h.Alias
			hostname = h.Hostname
			users = strings.Join(h.AccountNames(), ", ")
			port = h.Port
			m.formDefaultAuth = h.DefaultAuthType
			m.formDefaultEncPassword = cloneFormBytes(h.DefaultEncPassword)
			m.formUserConfigs = make([]formUserConfig, 0, len(h.Accounts))
			for _, account := range h.Accounts {
				m.formUserConfigs = append(m.formUserConfigs, formUserConfig{
					Username:            account.Username,
					UseDefault:          account.UseDefault,
					AuthType:            account.AuthType,
					ExistingEncPassword: cloneFormBytes(account.EncPassword),
				})
			}
			break
		}
	}

	m.formInputs = newHostFormInputs(alias, hostname, users, port)
	m.syncFormUsers()
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
		case "left", "h":
			switch m.formFocus {
			case fSelectedUser:
				m.selectFormUser(-1)
				return m, nil
			case fDefaultAuth:
				m.selectDefaultAuth(-1)
				return m, nil
			case fSelectedUserAuth:
				m.selectSelectedUserAuth(-1)
				return m, nil
			}
		case "right", "l":
			switch m.formFocus {
			case fSelectedUser:
				m.selectFormUser(1)
				return m, nil
			case fDefaultAuth:
				m.selectDefaultAuth(1)
				return m, nil
			case fSelectedUserAuth:
				m.selectSelectedUserAuth(1)
				return m, nil
			}
		case "enter":
			return m.submitHostForm()
		}
	}

	if idx := formInputIdx(m.formFocus); idx >= 0 {
		var cmd tea.Cmd
		m.formInputs[idx], cmd = m.formInputs[idx].Update(msg)
		switch m.formFocus {
		case fUsers:
			m.syncFormUsers()
		case fSelectedUserPassword:
			m.storeSelectedUserPasswordInput()
		}
		return m, cmd
	}

	return m, nil
}

func (m model) cycleFormFocus(dir int) (tea.Model, tea.Cmd) {
	if idx := formInputIdx(m.formFocus); idx >= 0 {
		m.formInputs[idx].Blur()
	}

	focuses := m.activeFormFocuses()
	if len(focuses) == 0 {
		return m, nil
	}

	cur := 0
	for i, focus := range focuses {
		if focus == m.formFocus {
			cur = i
			break
		}
	}

	cur = (cur + dir + len(focuses)) % len(focuses)
	m.formFocus = focuses[cur]

	if idx := formInputIdx(m.formFocus); idx >= 0 {
		m.formInputs[idx].Focus()
		return m, textinput.Blink
	}
	return m, nil
}

func (m model) activeFormFocuses() []int {
	focuses := []int{fAlias, fHostname, fUsers, fPort, fDefaultAuth}
	if m.formDefaultAuth == "password" {
		focuses = append(focuses, fDefaultPassword)
	}
	if len(m.formUserConfigs) == 0 {
		return focuses
	}

	focuses = append(focuses, fSelectedUser, fSelectedUserAuth)
	if user := m.currentFormUser(); user != nil && !user.UseDefault && user.AuthType == "password" {
		focuses = append(focuses, fSelectedUserPassword)
	}
	return focuses
}

func (m model) submitHostForm() (tea.Model, tea.Cmd) {
	alias := strings.TrimSpace(m.formInputs[0].Value())
	hostname := strings.TrimSpace(m.formInputs[1].Value())
	users := parseUsers(m.formInputs[2].Value())
	portStr := strings.TrimSpace(m.formInputs[3].Value())
	defaultPassword := m.formInputs[4].Value()

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

	h := host.Host{
		Alias:           alias,
		Hostname:        hostname,
		Port:            port,
		DefaultAuthType: m.formDefaultAuth,
		Accounts:        make([]host.HostUser, 0, len(m.formUserConfigs)),
	}

	if m.formDefaultAuth == "password" {
		switch {
		case defaultPassword != "":
			enc, err := vault.Encrypt(m.encKey, []byte(defaultPassword))
			if err != nil {
				m.formErr = "Failed to encrypt default password: " + err.Error()
				return m, nil
			}
			h.DefaultEncPassword = enc
		case len(m.formDefaultEncPassword) > 0:
			h.DefaultEncPassword = cloneFormBytes(m.formDefaultEncPassword)
		default:
			m.formErr = "Default password is required for password auth"
			return m, nil
		}
	}

	for _, cfg := range m.formUserConfigs {
		account := host.HostUser{
			Username:   cfg.Username,
			UseDefault: cfg.UseDefault,
		}
		if !cfg.UseDefault {
			account.AuthType = cfg.AuthType
			if cfg.AuthType == "password" {
				switch {
				case cfg.Password != "":
					enc, err := vault.Encrypt(m.encKey, []byte(cfg.Password))
					if err != nil {
						m.formErr = "Failed to encrypt password for " + cfg.Username + ": " + err.Error()
						return m, nil
					}
					account.EncPassword = enc
				case len(cfg.ExistingEncPassword) > 0:
					account.EncPassword = cloneFormBytes(cfg.ExistingEncPassword)
				default:
					m.formErr = "Override password is required for " + cfg.Username
					return m, nil
				}
			}
		}
		h.Accounts = append(h.Accounts, account)
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
		lbl := inputLabelStyle.Render(label)
		if m.formFocus == focus {
			lbl = focusedLabel("▸ " + label)
		}
		b.WriteString(lbl + "\n")
		b.WriteString(m.formInputs[idx].View() + "\n\n")
	}

	renderField(fAlias, "Alias", 0)
	renderField(fHostname, "Hostname", 1)
	renderField(fUsers, "Users", 2)
	b.WriteString(hintStyle.Render("  Comma-separated usernames. Example: root, ubuntu, deploy") + "\n\n")
	renderField(fPort, "Port", 3)

	b.WriteString(m.renderDefaultAuthSection())

	if len(m.formUserConfigs) > 0 {
		b.WriteString(m.renderSelectedUserSection())
	}

	if m.formErr != "" {
		b.WriteString(errorStyle.Render("✗ "+m.formErr) + "\n\n")
	}

	b.WriteString(statusBarStyle.Render("tab/↑↓ navigate • ←→ adjust selection • enter save • esc cancel"))
	return boxStyle.Render(b.String())
}

func (m model) renderDefaultAuthSection() string {
	var b strings.Builder
	lbl := inputLabelStyle.Render("Default Auth")
	if m.formFocus == fDefaultAuth {
		lbl = focusedLabel("▸ Default Auth")
	}
	b.WriteString(lbl + "\n")
	b.WriteString("  " + authChoice("SSH Key", m.formDefaultAuth == "key") + "    " +
		authChoice("Password", m.formDefaultAuth == "password"))
	if m.formFocus == fDefaultAuth {
		b.WriteString(hintStyle.Render("  (left/right to change)"))
	}
	b.WriteString("\n\n")

	if m.formDefaultAuth == "password" {
		fieldLabel := "Default Password"
		renderLabel := inputLabelStyle.Render(fieldLabel)
		if m.formFocus == fDefaultPassword {
			renderLabel = focusedLabel("▸ " + fieldLabel)
		}
		b.WriteString(renderLabel + "\n")
		b.WriteString(m.formInputs[4].View() + "\n")
		if m.formEditing != "" && len(m.formDefaultEncPassword) > 0 {
			b.WriteString(hintStyle.Render("  Leave empty to keep the current default password") + "\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

func (m model) renderSelectedUserSection() string {
	user := m.currentFormUser()
	if user == nil {
		return ""
	}

	var b strings.Builder
	lbl := inputLabelStyle.Render("Selected User")
	if m.formFocus == fSelectedUser {
		lbl = focusedLabel("▸ Selected User")
	}
	b.WriteString(lbl + "\n")
	b.WriteString("  " + m.renderUserTabs())
	if m.formFocus == fSelectedUser {
		b.WriteString(hintStyle.Render("  (left/right to switch)"))
	}
	b.WriteString("\n\n")

	modeLabel := inputLabelStyle.Render("User Auth")
	if m.formFocus == fSelectedUserAuth {
		modeLabel = focusedLabel("▸ User Auth")
	}
	b.WriteString(modeLabel + "\n")
	b.WriteString("  " + authChoice("Use Host Default", user.UseDefault) + "    " +
		authChoice("Password Override", !user.UseDefault && user.AuthType == "password") + "    " +
		authChoice("SSH Key Override", !user.UseDefault && user.AuthType == "key"))
	if m.formFocus == fSelectedUserAuth {
		b.WriteString(hintStyle.Render("  (left/right to change)"))
	}
	b.WriteString("\n")
	b.WriteString(hintStyle.Render("  Default means this user uses the host's main auth settings.") + "\n\n")

	if !user.UseDefault && user.AuthType == "password" {
		fieldLabel := "Override Password"
		renderLabel := inputLabelStyle.Render(fieldLabel)
		if m.formFocus == fSelectedUserPassword {
			renderLabel = focusedLabel("▸ " + fieldLabel)
		}
		b.WriteString(renderLabel + "\n")
		b.WriteString(m.formInputs[5].View() + "\n")
		if m.formEditing != "" && len(user.ExistingEncPassword) > 0 {
			b.WriteString(hintStyle.Render("  Leave empty to keep the current password for this user") + "\n")
		}
		b.WriteString("\n")
	}

	return b.String()
}

func authChoice(label string, selected bool) string {
	if selected {
		return selectedChip("● " + label)
	}
	return lipgloss.NewStyle().
		Foreground(subtle).
		Render("○ " + label)
}

func (m model) renderUserTabs() string {
	var parts []string
	for i, cfg := range m.formUserConfigs {
		if i == m.formUserCursor {
			parts = append(parts, selectedChip(cfg.Username))
			continue
		}
		parts = append(parts, lipgloss.NewStyle().Foreground(subtle).Render(cfg.Username))
	}
	return strings.Join(parts, "  ")
}

func selectedChip(label string) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#111827")).
		Background(highlight).
		Bold(true).
		Padding(0, 1).
		Render(label)
}

func focusedLabel(label string) string {
	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#111827")).
		Background(accent).
		Bold(true).
		Padding(0, 1).
		Render(label)
}

func (m *model) selectDefaultAuth(dir int) {
	if dir < 0 {
		m.formDefaultAuth = "key"
		return
	}
	m.formDefaultAuth = "password"
}

func (m *model) selectSelectedUserAuth(dir int) {
	user := m.currentFormUser()
	if user == nil {
		return
	}

	options := []struct {
		useDefault bool
		authType   string
	}{
		{useDefault: true, authType: ""},
		{useDefault: false, authType: "password"},
		{useDefault: false, authType: "key"},
	}

	index := 0
	switch {
	case user.UseDefault:
		index = 0
	case user.AuthType == "password":
		index = 1
	default:
		index = 2
	}

	index = (index + dir + len(options)) % len(options)
	user.UseDefault = options[index].useDefault
	user.AuthType = options[index].authType
	m.loadSelectedUserPasswordInput()
}

func (m *model) selectFormUser(delta int) {
	if len(m.formUserConfigs) == 0 {
		return
	}
	m.storeSelectedUserPasswordInput()
	m.formUserCursor = (m.formUserCursor + delta + len(m.formUserConfigs)) % len(m.formUserConfigs)
	m.loadSelectedUserPasswordInput()
}

func (m *model) currentFormUser() *formUserConfig {
	if len(m.formUserConfigs) == 0 {
		return nil
	}
	if m.formUserCursor < 0 {
		m.formUserCursor = 0
	}
	if m.formUserCursor >= len(m.formUserConfigs) {
		m.formUserCursor = len(m.formUserConfigs) - 1
	}
	return &m.formUserConfigs[m.formUserCursor]
}

func (m *model) syncFormUsers() {
	names := parseUsers(m.formInputs[2].Value())
	existing := make(map[string]formUserConfig, len(m.formUserConfigs))
	for _, cfg := range m.formUserConfigs {
		existing[cfg.Username] = cfg
	}

	next := make([]formUserConfig, 0, len(names))
	for _, name := range names {
		if cfg, ok := existing[name]; ok {
			cfg.Username = name
			next = append(next, cfg)
			continue
		}
		next = append(next, formUserConfig{
			Username:   name,
			UseDefault: true,
		})
	}

	m.formUserConfigs = next
	if len(m.formUserConfigs) == 0 {
		m.formUserCursor = 0
		m.formInputs[5].SetValue("")
		return
	}
	if m.formUserCursor >= len(m.formUserConfigs) {
		m.formUserCursor = len(m.formUserConfigs) - 1
	}
	m.loadSelectedUserPasswordInput()
}

func (m *model) loadSelectedUserPasswordInput() {
	user := m.currentFormUser()
	if user == nil {
		m.formInputs[5].SetValue("")
		return
	}
	m.formInputs[5].SetValue(user.Password)
}

func (m *model) storeSelectedUserPasswordInput() {
	user := m.currentFormUser()
	if user == nil {
		return
	}
	user.Password = m.formInputs[5].Value()
}

func parseUsers(raw string) []string {
	parts := strings.Split(raw, ",")
	seen := make(map[string]struct{}, len(parts))
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ok := seen[part]; ok {
			continue
		}
		seen[part] = struct{}{}
		out = append(out, part)
	}
	return out
}

func cloneFormBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	out := make([]byte, len(src))
	copy(out, src)
	return out
}
