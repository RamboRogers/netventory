package views

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// NetworkSelectionView handles the network selection screen
type NetworkSelectionView struct {
	styles *Styles
	width  int
	height int
}

// NewNetworkSelectionView creates a new network selection view
func NewNetworkSelectionView(styles *Styles) *NetworkSelectionView {
	return &NetworkSelectionView{
		styles: styles,
	}
}

// SetDimensions updates the view dimensions
func (v *NetworkSelectionView) SetDimensions(width, height int) {
	v.width = width
	v.height = height
}

// Render generates the view
func (v *NetworkSelectionView) Render(iface Interface) string {
	var content strings.Builder

	// Create styles for interface details
	labelStyle := v.styles.DialogText.Copy().
		Width(14).
		Align(lipgloss.Right).
		Foreground(lipgloss.Color("#00ff00"))

	valueStyle := v.styles.DialogText.Copy().
		Foreground(lipgloss.Color("#FFFFFF"))

	// Interface details
	content.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Center,
		labelStyle.Render("IP Address"),
		"  ",
		valueStyle.Render(iface.IPAddress),
	))
	content.WriteString("\n")

	content.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Center,
		labelStyle.Render("Subnet Mask"),
		"  ",
		valueStyle.Render(iface.SubnetMask),
	))
	content.WriteString("\n")

	content.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Center,
		labelStyle.Render("Gateway"),
		"  ",
		valueStyle.Render(iface.Gateway),
	))
	content.WriteString("\n")

	content.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Center,
		labelStyle.Render("MAC Address"),
		"  ",
		valueStyle.Render(iface.MACAddress),
	))

	return v.styles.DialogBox.Render(content.String())
}
