package tui

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/managedssh/managedssh/internal/analytics"
	"github.com/managedssh/managedssh/internal/audit"
	"github.com/managedssh/managedssh/internal/health"
	"github.com/managedssh/managedssh/internal/host"
	"github.com/managedssh/managedssh/internal/rbac"
	"github.com/managedssh/managedssh/internal/session"
	"github.com/managedssh/managedssh/internal/sshclient"
	"github.com/managedssh/managedssh/internal/vault"
)

// healthDoneMsg carries health check results back to the model.
type healthDoneMsg struct {
	results []health.Result
}

// ------------------------------------------------------------------
// Update
// ------------------------------------------------------------------

func (m model) updateDashboard(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case healthDoneMsg:
		m.healthResults = msg.results
		m.connErr = fmt.Sprintf("Health check complete: %d hosts checked", len(msg.results))
		return m, nil
	}
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

	can := func(p rbac.Permission) bool {
		if m.rbacConfig == nil {
			return true
		}
		return m.rbacConfig.Can(p)
	}
	deny := func(action string) {
		role := rbac.RoleAdmin
		if m.rbacConfig != nil {
			role = m.rbacConfig.Role
		}
		m.connErr = fmt.Sprintf("Permission denied: %s role cannot %s", role, action)
	}

	switch key.String() {
	case "q":
		vault.ZeroKey(m.encKey)
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
		if !can(rbac.PermAddHost) {
			deny("add hosts")
			return m, nil
		}
		m, cmd := m.startHostForm("")
		return m, cmd
	case "e":
		if !can(rbac.PermEditHost) {
			deny("edit hosts")
			return m, nil
		}
		if len(m.filtered) > 0 {
			h := m.filtered[m.hostCursor]
			m, cmd := m.startHostForm(h.ID)
			return m, cmd
		}
	case "d":
		if !can(rbac.PermDeleteHost) {
			deny("delete hosts")
			return m, nil
		}
		if len(m.filtered) > 0 {
			if m.confirmDelete {
				h := m.filtered[m.hostCursor]
				if err := m.store.Delete(h.ID); err != nil {
					m.connErr = "Delete failed: " + err.Error()
				} else {
					m.logAudit(audit.Event{
						Type:      "host_deleted",
						HostAlias: h.Alias,
						Hostname:  h.Hostname,
						Success:   true,
					})
				}
				m.confirmDelete = false
				m = m.refreshFiltered()
			} else {
				m.confirmDelete = true
			}
		}
	case "c":
		if !can(rbac.PermChangeKey) {
			deny("change master key")
			return m, nil
		}
		m = m.startChangeKey()
		return m, textinput.Blink
	case "l":
		vault.ZeroKey(m.encKey)
		m.encKey = nil
		m.store = nil
		m.filtered = nil
		m.rbacConfig = nil
		m.phase = phaseUnlock
		m.input = newPasswordInput("Locked — enter master key...")
		m.err = ""
		return m, textinput.Blink
	case "h":
		if !can(rbac.PermHealthCheck) {
			deny("run health checks")
			return m, nil
		}
		// Health check all visible hosts.
		hosts := make([]health.Host, len(m.filtered))
		for i, fh := range m.filtered {
			hosts[i] = health.Host{ID: fh.ID, Hostname: fh.Hostname, Port: fh.Port}
		}
		m.connErr = "Running health checks..."
		return m, func() tea.Msg {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			results := health.CheckAll(ctx, hosts, 5*time.Second, 10)
			return healthDoneMsg{results: results}
		}
	case "s":
		if !can(rbac.PermViewAnalytics) {
			deny("view analytics")
			return m, nil
		}
		// Show analytics summary.
		if m.auditLog != nil {
			events, err := m.auditLog.Recent(0)
			if err == nil {
				stats := analytics.Compute(events)
				m.connErr = fmt.Sprintf("Stats: %d connections, %.0f%% success, %d hosts, %d users",
					stats.TotalConnections, stats.SuccessRate, stats.UniqueHosts, stats.UniqueUsers)
			}
		}
		return m, nil
	case "enter":
		if !can(rbac.PermConnect) {
			deny("connect")
			return m, nil
		}
		if len(m.filtered) > 0 {
			h := m.filtered[m.hostCursor]
			users := h.UserList()
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

func (m model) logAudit(ev audit.Event) {
	if m.auditLog != nil {
		_ = m.auditLog.Record(ev)
	}
}

func (m model) connectSSH(h host.Host, user string) (tea.Model, tea.Cmd) {
	m.phase = phaseDashboard
	m.selectedHost = host.Host{}

	var password []byte
	if h.AuthType == "password" && len(h.EncPassword) > 0 {
		dec, err := vault.Decrypt(m.encKey, h.EncPassword)
		if err != nil {
			m.connErr = "Stored password could not be decrypted"
			m.logAudit(audit.Event{
				Type:      "ssh_connection",
				HostAlias: h.Alias,
				Hostname:  h.Hostname,
				User:      user,
				Port:      h.Port,
				Success:   false,
				Error:     "stored password could not be decrypted",
			})
			return m, nil
		}
		password = dec
	}

	connStart := time.Now()

	sess := &sshclient.Session{
		Host:     h.Hostname,
		Port:     h.Port,
		User:     user,
		Password: password,
		Timeout:  h.ConnTimeoutDuration(),
	}

	// Set up session recording if vault dir is available.
	var recorder *session.Recorder
	if dir, err := vault.Dir(); err == nil {
		sessDir := filepath.Join(dir, "sessions")
		if rec, err := session.NewRecorder(sessDir, h.Alias, user); err == nil {
			recorder = rec
			sess.Capture = rec
		}
	}

	hostAlias := h.Alias
	hostname := h.Hostname
	port := h.Port
	hostID := h.ID
	auditLog := m.auditLog
	store := m.store

	return m, tea.Exec(sess, func(err error) tea.Msg {
		if recorder != nil {
			recorder.Close()
		}
		ev := audit.Event{
			Type:      "ssh_connection",
			HostAlias: hostAlias,
			Hostname:  hostname,
			User:      user,
			Port:      port,
			Success:   err == nil,
			Duration:  time.Since(connStart).Round(time.Second).String(),
		}
		if err != nil {
			ev.Error = err.Error()
		} else if store != nil {
			_ = store.TouchConnected(hostID)
		}
		if auditLog != nil {
			_ = auditLog.Record(ev)
		}
		return sshDoneMsg{err: err}
	})
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

	// Title with profile + role indicator.
	profile := vault.ActiveProfile()
	if profile == "" {
		profile = "default"
	}
	titleText := "⚡ ManagedSSH"
	if profile != "default" {
		titleText += " [" + profile + "]"
	}
	if m.rbacConfig != nil && m.rbacConfig.Role != rbac.RoleAdmin {
		titleText += " (" + string(m.rbacConfig.Role) + ")"
	}
	title := titleStyle.Render(titleText)

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
		if strings.Contains(m.connErr, "successfully") || strings.Contains(m.connErr, "Stats:") || strings.Contains(m.connErr, "complete") {
			view += "\n" + successStyle.Render(" ✓ "+m.connErr)
		} else if strings.Contains(m.connErr, "Permission denied") {
			view += "\n" + lipgloss.NewStyle().Foreground(lipgloss.Color("#FBBF24")).Bold(true).Render(" ⚠ "+m.connErr)
		} else {
			view += "\n" + errorStyle.Render(" ✗ "+m.connErr)
		}
	}

	return lipgloss.Place(w, h, lipgloss.Center, lipgloss.Center, view)
}

// ------------------------------------------------------------------
// Render helpers
// ------------------------------------------------------------------

func (m model) renderHostList(maxW, maxH int) string {
	if len(m.filtered) == 0 {
		msg := "No hosts yet."
		if m.rbacConfig != nil && m.rbacConfig.Can(rbac.PermAddHost) {
			msg += "\n\nPress " + cmdKeyStyle.Render("a") + " to add your first host."
		}
		return lipgloss.NewStyle().Foreground(subtle).Render(msg)
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

		// Health indicator.
		healthIcon := ""
		for _, r := range m.healthResults {
			if r.HostID == h.ID {
				if r.Alive {
					healthIcon = lipgloss.NewStyle().Foreground(success).Render("●")
				} else {
					healthIcon = lipgloss.NewStyle().Foreground(danger).Render("●")
				}
				break
			}
		}

		groupTag := ""
		if h.Group != "" {
			groupTag = lipgloss.NewStyle().Foreground(subtle).Render(" [" + h.Group + "]")
		}

		line := fmt.Sprintf("%s%-*s %s", cursor, aliasW, alias, h.Hostname)
		rendered := style.Render(line) + groupTag
		if healthIcon != "" {
			rendered = healthIcon + " " + rendered
		}
		b.WriteString(rendered)
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
	if h.AuthType == "password" {
		authLabel = "Password"
	}

	render := func(label, value string) string {
		return detailLabelStyle.Render("  "+label) + detailValueStyle.Render(value)
	}

	lines := []string{
		render("Alias", h.Alias),
		render("Host", h.Hostname),
		render("Users", strings.Join(h.UserList(), ", ")),
		render("Port", fmt.Sprintf("%d", h.Port)),
		render("Auth", authLabel),
	}
	if h.Group != "" {
		lines = append(lines, render("Group", h.Group))
	}
	if len(h.Tags) > 0 {
		lines = append(lines, render("Tags", strings.Join(h.Tags, ", ")))
	}
	if h.ConnTimeout > 0 {
		lines = append(lines, render("Timeout", fmt.Sprintf("%ds", h.ConnTimeout)))
	}
	if h.LastConnectedAt != "" {
		lines = append(lines, render("Last", h.LastConnectedAt))
	}

	// Health result for this host.
	for _, r := range m.healthResults {
		if r.HostID == h.ID {
			status := lipgloss.NewStyle().Foreground(success).Render("Reachable")
			if !r.Alive {
				status = lipgloss.NewStyle().Foreground(danger).Render("Unreachable")
			}
			latency := fmt.Sprintf(" (%s)", r.Latency.Round(time.Millisecond))
			lines = append(lines, render("Health", status+latency))
			break
		}
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
	can := func(p rbac.Permission) bool {
		return m.rbacConfig == nil || m.rbacConfig.Can(p)
	}

	col := 18
	lines := "  " + pad(cmd("/", "search"), col)
	if can(rbac.PermHealthCheck) {
		lines += cmd("h", "health")
	}
	lines += "\n"
	lines += "  "
	if can(rbac.PermViewAnalytics) {
		lines += pad(cmd("s", "stats"), col)
	} else {
		lines += pad("", col)
	}
	lines += cmd("l", "lock") + "\n"

	if can(rbac.PermAddHost) {
		lines += "  " + pad(cmd("a", "add"), col)
	} else {
		lines += "  " + pad("", col)
	}
	if can(rbac.PermEditHost) {
		lines += cmd("e", "edit") + "\n"
	} else {
		lines += "\n"
	}
	if can(rbac.PermDeleteHost) {
		lines += "  " + pad(cmd("d", "delete"), col)
	} else {
		lines += "  " + pad("", col)
	}
	if can(rbac.PermConnect) {
		lines += cmd("⏎", "connect") + "\n"
	} else {
		lines += "\n"
	}
	if can(rbac.PermChangeKey) {
		lines += "  " + pad(cmd("c", "change key"), col)
	} else {
		lines += "  " + pad("", col)
	}
	lines += cmd("q", "quit")

	return lines
}

func (m model) updateUserSelect(msg tea.Msg) (tea.Model, tea.Cmd) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}

	users := m.selectedHost.UserList()
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
	users := m.selectedHost.UserList()

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
		b.WriteString(style.Render(prefix + user))
		if i < len(users)-1 {
			b.WriteByte('\n')
		}
	}

	b.WriteString("\n\n")
	b.WriteString(statusBarStyle.Render("↑↓ navigate • enter connect • esc back"))
	return boxStyle.Render(b.String())
}
