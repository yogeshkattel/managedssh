package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/managedssh/managedssh/internal/vault"
)

func (m model) updateChangeKeyInit(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc", "ctrl+c":
			m.phase = phaseDashboard
			m.input.Reset()
			m.err = ""
			m.connErr = "Master key change cancelled"
			return m, nil
		case "enter":
			val := m.input.Value()
			_, err := vault.Unlock(val)
			if err != nil {
				m.err = "Incorrect current master key"
				m.input.Reset()
				return m, nil
			}
			m.err = ""
			m.phase = phaseChangeKeyNew
			m.input = newPasswordInput("Enter NEW master key...")
			return m, textinput.Blink
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) viewChangeKeyInit() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("🔐 Change Master Key") + "\n")
	b.WriteString(subtitleStyle.Render("Enter your CURRENT master key to authorize.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("Current Key") + "\n")
	b.WriteString(m.input.View() + "\n\n")
	if m.err != "" {
		b.WriteString(errorStyle.Render("✗ " + m.err) + "\n\n")
	}
	b.WriteString(statusBarStyle.Render("enter confirm • esc cancel • ctrl+c quit"))
	return boxStyle.Render(b.String())
}

func (m model) updateChangeKeyNew(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc", "ctrl+c":
			m.phase = phaseDashboard
			m.input.Reset()
			m.err = ""
			m.connErr = "Master key change cancelled"
			return m, nil
		case "enter":
			val := m.input.Value()
			if len(val) < 8 {
				m.err = "Master key must be at least 8 characters"
				return m, nil
			}
			m.password = []byte(val)
			m.err = ""
			m.phase = phaseChangeKeyConfirm
			m.input = newPasswordInput("Confirm NEW master key...")
			return m, textinput.Blink
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) viewChangeKeyNew() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("🔐 Change Master Key") + "\n")
	b.WriteString(subtitleStyle.Render("Choose your NEW master key.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("New Key") + "\n")
	b.WriteString(m.input.View() + "\n\n")
	if m.err != "" {
		b.WriteString(errorStyle.Render("✗ " + m.err) + "\n\n")
	}
	b.WriteString(hintStyle.Render("Minimum 8 characters") + "\n")
	b.WriteString(statusBarStyle.Render("enter confirm • esc cancel • ctrl+c quit"))
	return boxStyle.Render(b.String())
}

func (m model) updateChangeKeyConfirm(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		switch key.String() {
		case "esc", "ctrl+c":
			m.phase = phaseChangeKeyNew
			zeroBytes(m.password)
			m.password = nil
			m.err = ""
			m.input = newPasswordInput("Enter NEW master key...")
			return m, textinput.Blink
		case "enter":
			val := m.input.Value()
			if val != string(m.password) {
				m.phase = phaseChangeKeyNew
				zeroBytes(m.password)
				m.password = nil
				m.err = "Keys do not match — please try again"
				m.input = newPasswordInput("Enter NEW master key...")
				return m, textinput.Blink
			}

			newKey, err := vault.Create(val)
			if err != nil {
				m.err = "Failed to create vault with new key"
				return m, nil
			}

			rewrap := func(field *[]byte) {
				if len(*field) > 0 {
					plain, err := vault.Decrypt(m.encKey, *field)
					if err == nil {
						if enc, err := vault.Encrypt(newKey, plain); err == nil {
							*field = enc
						}
						vault.ZeroKey(plain)
					}
				}
			}

			// In-place re-encryption
			for i := range m.store.Hosts {
				h := &m.store.Hosts[i]
				rewrap(&h.DefaultEncPassword)
				rewrap(&h.DefaultEncKey)
				rewrap(&h.DefaultEncKeyPass)
				rewrap(&h.EncPassword)
				
				for j := range h.Accounts {
					acc := &h.Accounts[j]
					rewrap(&acc.EncPassword)
					rewrap(&acc.EncKey)
					rewrap(&acc.EncKeyPass)
				}
			}

			if err := m.store.Save(); err != nil {
				m.err = "Failed to save re-encrypted hosts: " + err.Error()
				return m, nil
			}

			zeroBytes(m.encKey)
			m.encKey = newKey
			zeroBytes(m.password)
			m.password = nil

			m.phase = phaseDashboard
			m.connErr = ""
			m.err = ""
			m.input.Reset()
			return m, nil
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(msg)
	return m, cmd
}

func (m model) viewChangeKeyConfirm() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("🔐 Confirm New Key") + "\n")
	b.WriteString(subtitleStyle.Render("Type your NEW master key again to confirm.") + "\n\n")
	b.WriteString(inputLabelStyle.Render("Confirm Key") + "\n")
	b.WriteString(m.input.View() + "\n\n")
	if m.err != "" {
		b.WriteString(errorStyle.Render("✗ " + m.err) + "\n\n")
	}
	b.WriteString(statusBarStyle.Render("enter confirm • esc go back • ctrl+c quit"))
	return boxStyle.Render(b.String())
}
