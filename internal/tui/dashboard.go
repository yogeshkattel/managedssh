package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/managedssh/managedssh/internal/host"
	"github.com/managedssh/managedssh/internal/sshclient"
	"github.com/managedssh/managedssh/internal/vault"
)

// ------------------------------------------------------------------
// Update
// ------------------------------------------------------------------

func (m model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	if m.searchFocused {
		return m.updateDashboardSearch(msg)
	}
	return m.updateDashboardNormal(msg)
}

func (m model) updateDashboardSearch(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc":
			m.searchFocused = false
			m.search.Blur()
			m.search.Reset()
			m = m.refreshFiltered()
			return m, nil
		case "enter", "down":
			m.searchFocused = false
			m.search.Blur()
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.search, cmd = m.search.Update(msg)
	m = m.refreshFiltered()
	return m, cmd
}

func (m model) updateDashboardNormal(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	m.connErr = ""

	if m.confirmDelete && key.String() != "d" {
		m.confirmDelete = false
	}

	switch key.String() {
	case "q":
		m.quitting = true
		return m, tea.Quit
	case "j", "down":
		if m.hostCursor < len(m.filtered)-1 {
			m.hostCursor++
		}
	case "k", "up":
		if m.hostCursor > 0 {
			m.hostCursor--
		}
	case "/":
		m.searchFocused = true
		m.search.Focus()
		return m, textinput.Blink
	case "esc":
		if m.search.Value() != "" {
			m.search.Reset()
			m = m.refreshFiltered()
		}
	case "a":
		m, cmd := m.startHostForm("")
		return m, cmd
	case "e":
		if len(m.filtered) > 0 {
			h := m.filtered[m.hostCursor]
			m, cmd := m.startHostForm(h.ID)
			return m, cmd
		}
	case "d":
		if len(m.filtered) > 0 {
			if m.confirmDelete {
				h := m.filtered[m.hostCursor]
				if err := m.store.Delete(h.ID); err != nil {
					m.connErr = "Delete failed: " + err.Error()
				}
				m.confirmDelete = false
				m = m.refreshFiltered()
			} else {
				m.confirmDelete = true
			}
		}
	case "enter":
		if len(m.filtered) > 0 {
			h := m.filtered[m.hostCursor]
			users := h.AccountNames()
			if len(users) == 0 {
				m.connErr = "No users configured for this host"
				return m, nil
			}
			if len(users) == 1 {
				return m.connectSSH(h, users[0])
			}
			return m.startUserSelect(h), nil
		}
	}
	return m, nil
}

func (m model) connectSSH(h host.Host, user string) (tea.Model, tea.Cmd) {
	_, resolved, ok := h.ResolveAccount(user)
	if !ok {
		m.connErr = "Selected user is no longer available"
		return m, nil
	}

	return m.connectSSHWithResolved(h, user, resolved, nil, false)
}

func (m model) connectSSHWithResolved(h host.Host, user string, resolved host.ResolvedAuth, promptPassphrase []byte, savePrompt bool) (tea.Model, tea.Cmd) {
	m.phase = phaseDashboard
	m.selectedHost = host.Host{}
	m.connErr = ""

	var password []byte
	var keyData []byte
	var keyPath string
	var keyPassphrase []byte

	if resolved.AuthType == "password" && len(resolved.Password) > 0 {
		dec, err := vault.Decrypt(m.encKey, resolved.Password)
		if err == nil {
			password = dec
		}
	}
	if resolved.AuthType == "key" {
		keyPath = resolved.KeyPath
		if len(resolved.EncKey) > 0 {
			dec, err := vault.Decrypt(m.encKey, resolved.EncKey)
			if err == nil {
				keyData = dec
			}
		}
		if len(promptPassphrase) > 0 {
			keyPassphrase = append([]byte(nil), promptPassphrase...)
		} else if len(resolved.EncKeyPass) > 0 {
			dec, err := vault.Decrypt(m.encKey, resolved.EncKeyPass)
			if err == nil {
				keyPassphrase = dec
			}
		}
	}

	sess := &sshclient.Session{
		Host:          h.Hostname,
		Port:          h.Port,
		User:          user,
		Password:      password,
		KeyPath:       keyPath,
		KeyData:       keyData,
		KeyPassphrase: keyPassphrase,
	}

	m.connectHost = h
	m.connectUser = user
	m.connectResolved = resolved
	m.pendingKeyPassSave = savePrompt
	if !savePrompt {
		zeroBytes(m.pendingKeyPassphrase)
		m.pendingKeyPassphrase = nil
	}
	m.connectPassphraseInput.Reset()

	return m, tea.Exec(sess, func(err error) tea.Msg {
		return sshDoneMsg{err: err}
	})
}

func (m model) startKeyPassphrasePrompt(h host.Host, user string, resolved host.ResolvedAuth) model {
	m.phase = phaseKeyPassphrasePrompt
	m.connectHost = h
	m.connectUser = user
	m.connectResolved = resolved
	m.connectPassphraseInput = newKeyPassphraseInput()
	m.connErr = ""
	return m
}

func (m model) startUserSelect(h host.Host) model {
	m.phase = phaseUserSelect
	m.selectedHost = h
	m.userCursor = 0
	m.connErr = ""
	return m
}

// ------------------------------------------------------------------
// View
// ------------------------------------------------------------------

func (m model) viewDashboard() string {
	w := max(m.width, 80)
	h := max(m.height, 24)

	contentW := w - 4
	leftW := contentW * 55 / 100
	rightW := contentW - leftW - 1

	panelH := h - 7
	if panelH < 10 {
		panelH = 10
	}

	// Title
	title := titleStyle.Render("⚡ ManagedSSH")

	// Search bar
	searchIcon := lipgloss.NewStyle().Foreground(subtle).Render("🔍 ")
	if m.searchFocused {
		searchIcon = lipgloss.NewStyle().Foreground(highlight).Render("🔍 ")
	}
	searchLine := " " + searchIcon + m.search.View()
	if m.search.Value() != "" && !m.searchFocused {
		count := fmt.Sprintf("  %d/%d", len(m.filtered), len(m.store.Hosts))
		searchLine += lipgloss.NewStyle().Foreground(subtle).Render(count)
	}

	// Left panel — host list
	listTextW := leftW - 4
	listTextH := panelH - 4
	hostContent := m.renderHostList(listTextW, listTextH)

	leftPanel := panelBorder.
		Width(leftW).
		Height(panelH).
		Render(panelTitleStyle.Render(" Hosts") + "\n\n" + hostContent)

	// Right panels — details + commands
	detailH := panelH*2/3 - 1
	cmdH := panelH - detailH - 1

	detailContent := m.renderDetails()
	detailPanel := panelBorder.
		Width(rightW).
		Height(detailH).
		Render(panelTitleStyle.Render(" Server Details") + "\n\n" + detailContent)

	cmdContent := m.renderCommands()
	cmdPanel := panelBorder.
		Width(rightW).
		Height(cmdH).
		Render(panelTitleStyle.Render(" Commands") + "\n\n" + cmdContent)

	rightPanel := lipgloss.JoinVertical(lipgloss.Left, detailPanel, cmdPanel)
	panels := lipgloss.JoinHorizontal(lipgloss.Top, leftPanel, " ", rightPanel)

	view := title + "\n" + searchLine + "\n\n" + panels

	if m.connErr != "" {
		errBanner := errorStyle.Render(" ✗ " + m.connErr)
		view += "\n" + errBanner
	}

	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, view)
}

// ------------------------------------------------------------------
// Render helpers
// ------------------------------------------------------------------

func (m model) renderHostList(maxW, maxH int) string {
	if len(m.filtered) == 0 {
		empty := "No hosts yet.\n\nPress " +
			cmdKeyStyle.Render("a") + " to add your first host."
		return lipgloss.NewStyle().Foreground(subtle).Render(empty)
	}

	visible := maxH
	if visible < 1 {
		visible = 1
	}
	offset := 0
	if m.hostCursor >= visible {
		offset = m.hostCursor - visible + 1
	}
	end := offset + visible
	if end > len(m.filtered) {
		end = len(m.filtered)
	}

	aliasW := 16
	if maxW > 40 {
		aliasW = 20
	}

	var b strings.Builder
	for i := offset; i < end; i++ {
		h := m.filtered[i]

		cursor := "  "
		style := lipgloss.NewStyle().Foreground(text)
		if i == m.hostCursor {
			cursor = "▸ "
			style = lipgloss.NewStyle().Foreground(highlight).Bold(true)
		}

		alias := h.Alias
		if len(alias) > aliasW-1 {
			alias = alias[:aliasW-2] + "…"
		}

		line := fmt.Sprintf("%s%-*s %s", cursor, aliasW, alias, h.Hostname)
		b.WriteString(style.Render(line))
		if i < end-1 {
			b.WriteByte('\n')
		}
	}

	if len(m.filtered) > visible {
		b.WriteString("\n" + hintStyle.Render(fmt.Sprintf("  ↕ %d hosts total", len(m.filtered))))
	}

	return b.String()
}

func (m model) renderDetails() string {
	if len(m.filtered) == 0 {
		return hintStyle.Render("  No host selected")
	}
	h := m.filtered[m.hostCursor]

	authLabel := "SSH Key"
	if h.DefaultAuthType == "password" {
		authLabel = "Password"
	}

	render := func(label, value string) string {
		return detailLabelStyle.Render("  "+label) + detailValueStyle.Render(value)
	}

	lines := []string{
		render("Alias", h.Alias),
		render("Host", h.Hostname),
		render("Users", strings.Join(h.AccountNames(), ", ")),
		render("Port", fmt.Sprintf("%d", h.Port)),
		render("Default Auth", authLabel),
		render("Overrides", summarizeAccountOverrides(h)),
	}
	return strings.Join(lines, "\n")
}

func (m model) renderCommands() string {
	if m.confirmDelete {
		return errorStyle.Render("  Press d to confirm delete") + "\n" +
			hintStyle.Render("  Any other key to cancel")
	}

	cmd := func(key, desc string) string {
		return cmdKeyStyle.Render(key) + cmdDescStyle.Render(" "+desc)
	}
	pad := func(s string, w int) string {
		return lipgloss.NewStyle().Width(w).Render(s)
	}

	col := 16
	return "  " + pad(cmd("a", "add"), col) + cmd("e", "edit") + "\n" +
		"  " + pad(cmd("d", "delete"), col) + cmd("⏎", "connect/user") + "\n" +
		"  " + pad(cmd("/", "search"), col) + cmd("q", "quit")
}

func (m model) updateUserSelect(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	users := m.selectedHost.AccountNames()
	if len(users) == 0 {
		m.phase = phaseDashboard
		return m, nil
	}

	switch key.String() {
	case "esc":
		m.phase = phaseDashboard
		return m, nil
	case "j", "down":
		if m.userCursor < len(users)-1 {
			m.userCursor++
		}
	case "k", "up":
		if m.userCursor > 0 {
			m.userCursor--
		}
	case "enter":
		return m.connectSSH(m.selectedHost, users[m.userCursor])
	}

	return m, nil
}

func (m model) viewUserSelect() string {
	users := m.selectedHost.AccountNames()

	var b strings.Builder
	b.WriteString(titleStyle.Render("Choose SSH User") + "\n")
	b.WriteString(subtitleStyle.Render(m.selectedHost.Alias+" • "+m.selectedHost.Hostname) + "\n\n")

	for i, user := range users {
		prefix := "  "
		style := lipgloss.NewStyle().Foreground(text)
		if i == m.userCursor {
			prefix = "▸ "
			style = lipgloss.NewStyle().Foreground(highlight).Bold(true)
		}
		b.WriteString(style.Render(prefix + user + userSummarySuffix(m.selectedHost, user)))
		if i < len(users)-1 {
			b.WriteByte('\n')
		}
	}

	b.WriteString("\n\n")
	b.WriteString(statusBarStyle.Render("↑↓ navigate • enter connect • esc back"))
	return boxStyle.Render(b.String())
}

func summarizeAccountOverrides(h host.Host) string {
	var parts []string
	for _, account := range h.Accounts {
		if account.UseDefault {
			continue
		}
		label := account.Username + " (SSH Key)"
		if account.AuthType == "password" {
			label = account.Username + " (Password)"
		}
		parts = append(parts, label)
	}
	if len(parts) == 0 {
		return "None"
	}
	return strings.Join(parts, ", ")
}

func userSummarySuffix(h host.Host, username string) string {
	account, resolved, ok := h.ResolveAccount(username)
	if !ok {
		return ""
	}
	if account.UseDefault {
		return "  [default]"
	}
	if resolved.AuthType == "password" {
		return "  [password override]"
	}
	return "  [key override]"
}
