package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

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
			return m.connectSSH()
		}
	}
	return m, nil
}

func (m model) connectSSH() (tea.Model, tea.Cmd) {
	h := m.filtered[m.hostCursor]

	var password []byte
	if h.AuthType == "password" && len(h.EncPassword) > 0 {
		dec, err := vault.Decrypt(m.encKey, h.EncPassword)
		if err == nil {
			password = dec
		}
	}

	sess := &sshclient.Session{
		Host:     h.Hostname,
		Port:     h.Port,
		User:     h.User,
		Password: password,
	}

	return m, tea.Exec(sess, func(err error) tea.Msg {
		return sshDoneMsg{err: err}
	})
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
	if h.AuthType == "password" {
		authLabel = "Password"
	}

	render := func(label, value string) string {
		return detailLabelStyle.Render("  "+label) + detailValueStyle.Render(value)
	}

	lines := []string{
		render("Alias", h.Alias),
		render("Host", h.Hostname),
		render("User", h.User),
		render("Port", fmt.Sprintf("%d", h.Port)),
		render("Auth", authLabel),
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
		"  " + pad(cmd("d", "delete"), col) + cmd("⏎", "connect") + "\n" +
		"  " + pad(cmd("/", "search"), col) + cmd("q", "quit")
}
