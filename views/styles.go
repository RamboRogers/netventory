package views

import (
	"github.com/charmbracelet/lipgloss"
)

// Core colors
var (
	primaryColor    = lipgloss.Color("#39ff14") // Bright digital green
	secondaryColor  = lipgloss.Color("#FFFFFF") // Pure white for labels
	accentColor     = lipgloss.Color("#39ff14") // Bright green for borders
	highlightColor  = lipgloss.Color("#39ff14") // Bright green for values
	backgroundColor = lipgloss.Color("#000000") // Pure black
	boxBgColor      = lipgloss.Color("#000000") // Pure black for boxes

	// Scanner gradient (green only)
	scanColors = []lipgloss.Color{
		lipgloss.Color("#001100"), // Darkest green
		lipgloss.Color("#002200"),
		lipgloss.Color("#003300"),
		lipgloss.Color("#39ff14"), // Peak bright
		lipgloss.Color("#39ff14"), // Keep bright
		lipgloss.Color("#39ff14"), // Keep bright
		lipgloss.Color("#003300"),
		lipgloss.Color("#002200"),
	}
)

// Styles holds all the application styles
type Styles struct {
	Banner     lipgloss.Style
	Box        lipgloss.Style
	Info       lipgloss.Style
	InfoLabel  lipgloss.Style
	Help       lipgloss.Style
	DialogBox  lipgloss.Style
	RangeInput lipgloss.Style
	DialogText lipgloss.Style
	KeyStyle   lipgloss.Style
	DescStyle  lipgloss.Style
}

// NewStyles creates a new Styles instance
func NewStyles() *Styles {
	s := &Styles{}

	s.Banner = lipgloss.NewStyle().
		Bold(true).
		Foreground(primaryColor).
		Background(backgroundColor)

	s.Box = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(accentColor).
		Padding(2, 4).
		Background(boxBgColor).
		Width(50)

	s.Info = lipgloss.NewStyle().
		Foreground(highlightColor).
		Bold(true)

	s.InfoLabel = lipgloss.NewStyle().
		Foreground(secondaryColor).
		Width(15).
		Align(lipgloss.Right)

	s.Help = lipgloss.NewStyle().
		Foreground(secondaryColor).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(accentColor).
		Background(boxBgColor).
		Padding(1, 4).
		Align(lipgloss.Center)

	s.DialogBox = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(accentColor).
		Padding(1, 2).
		Background(boxBgColor).
		Width(60).
		Align(lipgloss.Center)

	s.RangeInput = lipgloss.NewStyle().
		Foreground(primaryColor).
		Background(boxBgColor).
		Bold(true)

	s.DialogText = lipgloss.NewStyle().
		Foreground(secondaryColor).
		Background(boxBgColor)

	s.KeyStyle = lipgloss.NewStyle().
		Foreground(primaryColor)

	s.DescStyle = lipgloss.NewStyle().
		Foreground(secondaryColor)

	return s
}

// RenderBanner creates the standard banner
func (s *Styles) RenderBanner() string {
	banner := []string{
		"───────────────── NetVentory ─────────────────",
		lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Render("Network Discovery & Inventory"),
		"───────────────────────────────────────────────",
	}

	bannerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(primaryColor).
		Background(backgroundColor).
		Width(50).       // Set minimum width
		MarginBottom(1). // Add space below
		Align(lipgloss.Center)

	return lipgloss.JoinVertical(
		lipgloss.Center,
		bannerStyle.Render(banner[0]),
		bannerStyle.Render(banner[1]),
		bannerStyle.Render(banner[2]),
	)
}
