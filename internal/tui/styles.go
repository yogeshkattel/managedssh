package tui

import "github.com/charmbracelet/lipgloss"

var (
	accent    = lipgloss.Color("#7C3AED")
	subtle    = lipgloss.Color("#6B7280")
	text      = lipgloss.Color("#E5E7EB")
	highlight = lipgloss.Color("#A78BFA")
	success   = lipgloss.Color("#34D399")
	danger    = lipgloss.Color("#F87171")

	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(accent).
			MarginBottom(1)

	subtitleStyle = lipgloss.NewStyle().
			Foreground(subtle).
			Italic(true)

	selectedStyle = lipgloss.NewStyle().
			Foreground(highlight).
			Bold(true).
			PaddingLeft(2)

	normalStyle = lipgloss.NewStyle().
			Foreground(text).
			PaddingLeft(4)

	statusBarStyle = lipgloss.NewStyle().
			Foreground(subtle).
			MarginTop(1).
			Italic(true)

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(accent).
			Padding(1, 2)

	inputLabelStyle = lipgloss.NewStyle().
			Foreground(highlight).
			Bold(true).
			MarginBottom(0)

	errorStyle = lipgloss.NewStyle().
			Foreground(danger).
			Bold(true)

	hintStyle = lipgloss.NewStyle().
			Foreground(subtle).
			Italic(true)

	successStyle = lipgloss.NewStyle().
			Foreground(success).
			Bold(true)

	panelBorder = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(accent).
			Padding(0, 1)

	panelTitleStyle = lipgloss.NewStyle().
			Foreground(accent).
			Bold(true)

	detailLabelStyle = lipgloss.NewStyle().
				Foreground(subtle).
				Width(10)

	detailValueStyle = lipgloss.NewStyle().
				Foreground(text).
				Bold(true)

	cmdKeyStyle = lipgloss.NewStyle().
			Foreground(highlight).
			Bold(true)

	cmdDescStyle = lipgloss.NewStyle().
			Foreground(text)
)
