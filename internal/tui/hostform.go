package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	fDefaultCredential
	fSelectedUser
	fSelectedUserAuth
	fSelectedUserCredential
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
	case fDefaultCredential:
		return 4
	case fSelectedUserCredential:
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
	inputs[4].CharLimit = 4096
	inputs[4].Width = 36

	inputs[5] = textinput.New()
	inputs[5].Placeholder = "Override password"
	inputs[5].CharLimit = 4096
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
	m.formDefaultPassword = ""
	m.formDefaultEncPassword = nil
	m.formDefaultKeyValue = ""
	m.formDefaultKeyPath = ""
	m.formDefaultEncKey = nil
	m.formUserConfigs = nil
	m.formUserCursor = 0
	m.formPathSuggestions = nil
	m.formPathSuggestIndex = 0

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
			m.formDefaultKeyPath = h.DefaultKeyPath
			m.formDefaultEncKey = cloneFormBytes(h.DefaultEncKey)
			if h.DefaultKeyPath != "" {
				m.formDefaultKeyValue = h.DefaultKeyPath
			}
			m.formUserConfigs = make([]formUserConfig, 0, len(h.Accounts))
			for _, account := range h.Accounts {
				keyValue := account.KeyPath
				m.formUserConfigs = append(m.formUserConfigs, formUserConfig{
					Username:            account.Username,
					UseDefault:          account.UseDefault,
					AuthType:            account.AuthType,
					ExistingEncPassword: cloneFormBytes(account.EncPassword),
					KeyValue:            keyValue,
					ExistingKeyPath:     account.KeyPath,
					ExistingEncKey:      cloneFormBytes(account.EncKey),
				})
			}
			break
		}
	}

	m.formInputs = newHostFormInputs(alias, hostname, users, port)
	m.loadDefaultCredentialInput()
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
		case "tab":
			if m.acceptPathSuggestion() {
				return m, nil
			}
			return m.cycleFormFocus(1)
		case "down":
			return m.cycleFormFocus(1)
		case "shift+tab", "up":
			return m.cycleFormFocus(-1)
		case "ctrl+n":
			if m.cyclePathSuggestion(1) {
				return m, nil
			}
		case "ctrl+p":
			if m.cyclePathSuggestion(-1) {
				return m, nil
			}
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
		case fDefaultCredential:
			if m.formDefaultAuth == "password" {
				m.formDefaultPassword = m.formInputs[4].Value()
			} else {
				m.storeDefaultCredentialInput()
			}
			m.refreshPathSuggestions()
		case fSelectedUserCredential:
			m.storeSelectedUserCredentialInput()
			m.refreshPathSuggestions()
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
		m.refreshPathSuggestions()
		m.formInputs[idx].Focus()
		return m, textinput.Blink
	}
	m.formPathSuggestions = nil
	m.formPathSuggestIndex = 0
	return m, nil
}

func (m model) activeFormFocuses() []int {
	focuses := []int{fAlias, fHostname, fUsers, fPort, fDefaultAuth}
	if m.formDefaultAuth == "password" || m.formDefaultAuth == "key" {
		focuses = append(focuses, fDefaultCredential)
	}
	if len(m.formUserConfigs) == 0 {
		return focuses
	}

	focuses = append(focuses, fSelectedUser, fSelectedUserAuth)
	if user := m.currentFormUser(); user != nil && !user.UseDefault && (user.AuthType == "password" || user.AuthType == "key") {
		focuses = append(focuses, fSelectedUserCredential)
	}
	return focuses
}

func (m model) submitHostForm() (tea.Model, tea.Cmd) {
	alias := strings.TrimSpace(m.formInputs[0].Value())
	hostname := strings.TrimSpace(m.formInputs[1].Value())
	users := parseUsers(m.formInputs[2].Value())
	portStr := strings.TrimSpace(m.formInputs[3].Value())
	defaultCredential := m.formInputs[4].Value()

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
		case defaultCredential != "":
			enc, err := vault.Encrypt(m.encKey, []byte(defaultCredential))
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
	} else {
		keyPath, keyPlain := splitKeyValue(defaultCredential)
		switch {
		case keyPath != "":
			h.DefaultKeyPath = keyPath
		case keyPlain != "":
			enc, err := vault.Encrypt(m.encKey, []byte(keyPlain))
			if err != nil {
				m.formErr = "Failed to encrypt default SSH key: " + err.Error()
				return m, nil
			}
			h.DefaultEncKey = enc
		case m.formDefaultKeyPath != "":
			h.DefaultKeyPath = m.formDefaultKeyPath
		case len(m.formDefaultEncKey) > 0:
			h.DefaultEncKey = cloneFormBytes(m.formDefaultEncKey)
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
			} else {
				keyPath, keyPlain := splitKeyValue(cfg.KeyValue)
				switch {
				case keyPath != "":
					account.KeyPath = keyPath
				case keyPlain != "":
					enc, err := vault.Encrypt(m.encKey, []byte(keyPlain))
					if err != nil {
						m.formErr = "Failed to encrypt SSH key for " + cfg.Username + ": " + err.Error()
						return m, nil
					}
					account.EncKey = enc
				case cfg.ExistingKeyPath != "":
					account.KeyPath = cfg.ExistingKeyPath
				case len(cfg.ExistingEncKey) > 0:
					account.EncKey = cloneFormBytes(cfg.ExistingEncKey)
				}
			}
		}
		h.Accounts = append(h.Accounts, account)
	}

	m.pendingHost = h
	m.pendingEditID = m.formEditing
	m.pendingTrust = nil
	m.phase = phaseHostVerifying
	m.formErr = ""
	return m, verifyHostCmd(h, m.encKey)
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
		if m.formFocus == fDefaultCredential {
			renderLabel = focusedLabel("▸ " + fieldLabel)
		}
		b.WriteString(renderLabel + "\n")
		b.WriteString(m.formInputs[4].View() + "\n")
		if m.formEditing != "" && len(m.formDefaultEncPassword) > 0 {
			b.WriteString(hintStyle.Render("  Leave empty to keep the current default password") + "\n")
		}
		b.WriteString("\n")
	} else {
		fieldLabel := "Default SSH Key"
		renderLabel := inputLabelStyle.Render(fieldLabel)
		if m.formFocus == fDefaultCredential {
			renderLabel = focusedLabel("▸ " + fieldLabel)
		}
		b.WriteString(renderLabel + "\n")
		b.WriteString(m.formInputs[4].View() + "\n")
		b.WriteString(hintStyle.Render("  Enter a key path or paste private key text. Use \\n for new lines if needed.") + "\n")
		b.WriteString(m.renderPathSuggestions())
		if m.formEditing != "" && hasDefaultKey(m) {
			b.WriteString(hintStyle.Render("  Leave empty to keep the current default SSH key") + "\n")
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
		if m.formFocus == fSelectedUserCredential {
			renderLabel = focusedLabel("▸ " + fieldLabel)
		}
		b.WriteString(renderLabel + "\n")
		b.WriteString(m.formInputs[5].View() + "\n")
		if m.formEditing != "" && len(user.ExistingEncPassword) > 0 {
			b.WriteString(hintStyle.Render("  Leave empty to keep the current password for this user") + "\n")
		}
		b.WriteString("\n")
	} else if !user.UseDefault && user.AuthType == "key" {
		fieldLabel := "Override SSH Key"
		renderLabel := inputLabelStyle.Render(fieldLabel)
		if m.formFocus == fSelectedUserCredential {
			renderLabel = focusedLabel("▸ " + fieldLabel)
		}
		b.WriteString(renderLabel + "\n")
		b.WriteString(m.formInputs[5].View() + "\n")
		b.WriteString(hintStyle.Render("  Enter a key path or paste private key text. Use \\n for new lines if needed.") + "\n")
		b.WriteString(m.renderPathSuggestions())
		if m.formEditing != "" && (user.ExistingKeyPath != "" || len(user.ExistingEncKey) > 0) {
			b.WriteString(hintStyle.Render("  Leave empty to keep the current SSH key for this user") + "\n")
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
		m.loadDefaultCredentialInput()
		m.refreshPathSuggestions()
		return
	}
	m.formDefaultAuth = "password"
	m.loadDefaultCredentialInput()
	m.refreshPathSuggestions()
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
	m.loadSelectedUserCredentialInput()
	m.refreshPathSuggestions()
}

func (m *model) selectFormUser(delta int) {
	if len(m.formUserConfigs) == 0 {
		return
	}
	m.storeSelectedUserCredentialInput()
	m.formUserCursor = (m.formUserCursor + delta + len(m.formUserConfigs)) % len(m.formUserConfigs)
	m.loadSelectedUserCredentialInput()
	m.refreshPathSuggestions()
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
		m.refreshPathSuggestions()
		return
	}
	if m.formUserCursor >= len(m.formUserConfigs) {
		m.formUserCursor = len(m.formUserConfigs) - 1
	}
	m.loadSelectedUserCredentialInput()
	m.refreshPathSuggestions()
}

func (m *model) loadDefaultCredentialInput() {
	configureCredentialInput(&m.formInputs[4], m.formDefaultAuth, "Default")
	if m.formDefaultAuth == "password" {
		m.formInputs[4].SetValue(m.formDefaultPassword)
		m.refreshPathSuggestions()
		return
	}
	m.formInputs[4].SetValue(m.formDefaultKeyValue)
	m.refreshPathSuggestions()
}

func (m *model) storeDefaultCredentialInput() {
	if m.formDefaultAuth == "password" {
		return
	}
	m.formDefaultKeyValue = strings.TrimSpace(m.formInputs[4].Value())
}

func (m *model) loadSelectedUserCredentialInput() {
	user := m.currentFormUser()
	if user == nil {
		m.formInputs[5].SetValue("")
		m.refreshPathSuggestions()
		return
	}
	configureCredentialInput(&m.formInputs[5], user.AuthType, "Override")
	switch user.AuthType {
	case "password":
		m.formInputs[5].SetValue(user.Password)
	case "key":
		m.formInputs[5].SetValue(user.KeyValue)
	default:
		m.formInputs[5].SetValue("")
	}
	m.refreshPathSuggestions()
}

func (m *model) storeSelectedUserCredentialInput() {
	user := m.currentFormUser()
	if user == nil {
		return
	}
	switch user.AuthType {
	case "password":
		user.Password = m.formInputs[5].Value()
	case "key":
		user.KeyValue = strings.TrimSpace(m.formInputs[5].Value())
	}
}

func configureCredentialInput(input *textinput.Model, authType, label string) {
	input.CharLimit = 4096
	input.Width = 36
	if authType == "password" {
		input.Placeholder = label + " password"
		input.EchoMode = textinput.EchoPassword
		input.EchoCharacter = '•'
		return
	}
	input.Placeholder = label + " SSH key path or private key"
	input.EchoMode = textinput.EchoNormal
}

func (m model) renderPathSuggestions() string {
	if len(m.formPathSuggestions) == 0 {
		return ""
	}
	var lines []string
	lines = append(lines, hintStyle.Render("  Path suggestions: tab accept • ctrl+n/ctrl+p move"))
	for i, suggestion := range m.formPathSuggestions {
		line := "  " + suggestion
		if i == m.formPathSuggestIndex {
			line = "  " + selectedChip(suggestion)
		} else {
			line = hintStyle.Render(line)
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n") + "\n"
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

func splitKeyValue(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if strings.Contains(raw, "BEGIN ") || strings.Contains(raw, "\\n") {
		return "", strings.ReplaceAll(raw, "\\n", "\n")
	}
	return raw, ""
}

func (m *model) activePathInput() (*textinput.Model, bool) {
	switch m.formFocus {
	case fDefaultCredential:
		if m.formDefaultAuth == "key" {
			return &m.formInputs[4], true
		}
	case fSelectedUserCredential:
		if user := m.currentFormUser(); user != nil && !user.UseDefault && user.AuthType == "key" {
			return &m.formInputs[5], true
		}
	}
	return nil, false
}

func (m *model) refreshPathSuggestions() {
	input, ok := m.activePathInput()
	if !ok {
		m.formPathSuggestions = nil
		m.formPathSuggestIndex = 0
		return
	}
	suggestions := completePathSuggestions(strings.TrimSpace(input.Value()))
	m.formPathSuggestions = suggestions
	if len(suggestions) == 0 {
		m.formPathSuggestIndex = 0
		return
	}
	if m.formPathSuggestIndex >= len(suggestions) {
		m.formPathSuggestIndex = 0
	}
}

func (m *model) cyclePathSuggestion(delta int) bool {
	if len(m.formPathSuggestions) == 0 {
		return false
	}
	m.formPathSuggestIndex = (m.formPathSuggestIndex + delta + len(m.formPathSuggestions)) % len(m.formPathSuggestions)
	return true
}

func (m *model) acceptPathSuggestion() bool {
	input, ok := m.activePathInput()
	if !ok || len(m.formPathSuggestions) == 0 {
		return false
	}
	suggestion := m.formPathSuggestions[m.formPathSuggestIndex]
	input.SetValue(suggestion)
	switch m.formFocus {
	case fDefaultCredential:
		m.storeDefaultCredentialInput()
	case fSelectedUserCredential:
		m.storeSelectedUserCredentialInput()
	}
	m.refreshPathSuggestions()
	return true
}

func completePathSuggestions(raw string) []string {
	if raw == "" {
		raw = "~/.ssh/"
	}
	if strings.Contains(raw, "BEGIN ") || strings.Contains(raw, "\\n") {
		return nil
	}

	expanded := expandUserPath(raw)
	dirPart := expanded
	prefix := ""
	if !strings.HasSuffix(expanded, string(os.PathSeparator)) {
		dirPart = filepath.Dir(expanded)
		prefix = filepath.Base(expanded)
	}
	if dirPart == "" {
		dirPart = "."
	}

	entries, err := os.ReadDir(dirPart)
	if err != nil {
		return nil
	}

	var matches []string
	for _, entry := range entries {
		name := entry.Name()
		if prefix != "" && !strings.HasPrefix(strings.ToLower(name), strings.ToLower(prefix)) {
			continue
		}
		full := filepath.Join(dirPart, name)
		display := collapseUserPath(full)
		if entry.IsDir() {
			display += string(os.PathSeparator)
		}
		matches = append(matches, display)
	}
	sort.Strings(matches)
	if len(matches) > 5 {
		matches = matches[:5]
	}
	return matches
}

func expandUserPath(path string) string {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			if path == "~" {
				return home
			}
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func collapseUserPath(path string) string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return path
	}
	if path == home {
		return "~"
	}
	prefix := home + string(os.PathSeparator)
	if strings.HasPrefix(path, prefix) {
		return "~/" + strings.TrimPrefix(path, prefix)
	}
	return path
}

func hasDefaultKey(m model) bool {
	return m.formDefaultKeyPath != "" || len(m.formDefaultEncKey) > 0
}

func cloneFormBytes(src []byte) []byte {
	if len(src) == 0 {
		return nil
	}
	out := make([]byte, len(src))
	copy(out, src)
	return out
}
