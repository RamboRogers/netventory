package views

import (
	"fmt"
	"net"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ConfirmView handles the network scan configuration screen
type ConfirmView struct {
	styles   *Styles
	width    int
	height   int
	selected Interface
	range_   string
	editing  bool
	cursor   int
}

// NewConfirmView creates a new confirmation view
func NewConfirmView(styles *Styles) *ConfirmView {
	return &ConfirmView{
		styles: styles,
	}
}

// SetDimensions updates the view dimensions
func (v *ConfirmView) SetDimensions(width, height int) {
	v.width = width
	v.height = height
}

// SetInterface updates the selected interface
func (v *ConfirmView) SetInterface(iface Interface) {
	v.selected = iface
}

// SetRange updates the network range
func (v *ConfirmView) SetRange(r string) {
	v.range_ = r
}

// SetEditing updates the editing state
func (v *ConfirmView) SetEditing(editing bool) {
	v.editing = editing
}

// SetCursor updates the cursor position
func (v *ConfirmView) SetCursor(pos int) {
	v.cursor = pos
}

// Render generates the view
func (v *ConfirmView) Render() string {
	// Create banner
	banner := v.styles.RenderBanner()

	// Create dialog content
	var content strings.Builder
	content.WriteString(v.styles.DialogText.Bold(true).Render("Network Scan Configuration"))
	content.WriteString("\n\n")

	// Interface section
	content.WriteString(v.styles.DialogText.Render("Selected Interface:"))
	content.WriteString("\n")
	interfaceInfo := fmt.Sprintf("%s (%s)", v.selected.Name, v.selected.IPAddress)
	content.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Render(interfaceInfo))
	content.WriteString("\n\n")

	// Network range section
	content.WriteString(v.styles.DialogText.Render("Network Range:"))
	content.WriteString("\n")

	// Show editable or static range with enhanced styling
	var rangeDisplay string
	if v.editing {
		before := v.range_[:v.cursor]
		after := v.range_[v.cursor:]
		cursor := "│"
		rangeDisplay = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Render(before + cursor + after)
	} else {
		rangeDisplay = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Render(v.range_)
	}
	content.WriteString(rangeDisplay)

	// Add network info if valid CIDR
	_, ipNet, _ := net.ParseCIDR(v.range_)
	if ipNet != nil {
		ones, bits := ipNet.Mask.Size()
		hosts := 1<<uint(bits-ones) - 2 // subtract network and broadcast addresses
		content.WriteString("\n\n")
		content.WriteString(lipgloss.JoinHorizontal(
			lipgloss.Left,
			v.styles.DialogText.Copy().Foreground(lipgloss.Color("#00ff00")).Render("Hosts to scan: "),
			v.styles.DialogText.Copy().Foreground(lipgloss.Color("#FFFFFF")).Render(fmt.Sprintf("%d", hosts)),
		))
	}

	content.WriteString("\n\n")

	// Add key bindings with enhanced styling
	keyHelp := []string{
		v.styles.KeyStyle.Render("e") + v.styles.DescStyle.Render(" Edit"),
		v.styles.KeyStyle.Render("↵") + v.styles.DescStyle.Render(" Confirm"),
		v.styles.KeyStyle.Render("esc") + v.styles.DescStyle.Render(" Cancel"),
	}
	content.WriteString(v.styles.Help.Render(strings.Join(keyHelp, " • ")))

	dialog := v.styles.DialogBox.Render(content.String())

	// Combine banner and dialog with proper spacing
	fullContent := lipgloss.JoinVertical(
		lipgloss.Center,
		banner,
		"\n",
		dialog,
	)

	// Center everything on screen
	return lipgloss.Place(
		v.width,
		v.height,
		lipgloss.Center,
		lipgloss.Center,
		fullContent,
	)
}
