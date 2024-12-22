package views

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// InterfacesView handles the interface selection screen
type InterfacesView struct {
	styles        *Styles
	width         int
	height        int
	interfaces    []Interface
	selectedIndex int
}

// NewInterfacesView creates a new interfaces view
func NewInterfacesView(styles *Styles) *InterfacesView {
	return &InterfacesView{
		styles: styles,
	}
}

// SetDimensions updates the view dimensions
func (v *InterfacesView) SetDimensions(width, height int) {
	v.width = width
	v.height = height
}

// SetInterfaces updates the list of interfaces
func (v *InterfacesView) SetInterfaces(interfaces []Interface) {
	v.interfaces = interfaces
}

// SetSelectedIndex updates the selected interface index
func (v *InterfacesView) SetSelectedIndex(index int) {
	v.selectedIndex = index
}

// Render generates the view
func (v *InterfacesView) Render() string {
	// Create banner
	banner := v.styles.RenderBanner()

	// Create title
	title := v.styles.DialogText.
		Bold(true).
		Padding(0, 1).
		Foreground(primaryColor).
		Align(lipgloss.Center).
		Render("Select Network Interface")

	// Create interface list
	var listContent []string
	for i, iface := range v.interfaces {
		displayName := iface.Name
		if runtime.GOOS == "windows" {
			displayName = iface.FriendlyName
		}
		item := fmt.Sprintf("%s (%s)", displayName, iface.IPAddress)
		if i == v.selectedIndex {
			arrow := v.styles.RangeInput.Copy().
				Foreground(lipgloss.Color("#00ff00")).
				Render("▶")
			text := v.styles.DialogText.Copy().
				Foreground(lipgloss.Color("#FFFFFF")).
				Render(" " + item)
			item = arrow + text
		} else {
			item = v.styles.DialogText.Copy().
				Foreground(lipgloss.Color("#FFFFFF")).
				Render("  " + item)
		}
		listContent = append(listContent, item)
	}

	list := v.styles.DialogBox.Render(strings.Join(listContent, "\n"))

	// Create details box
	var details string
	if len(v.interfaces) > 0 {
		selected := v.interfaces[v.selectedIndex]
		nameDisplay := selected.Name
		if runtime.GOOS == "windows" && selected.FriendlyName != selected.Name {
			nameDisplay = fmt.Sprintf("%s (%s)", selected.FriendlyName, selected.Name)
		}
		details = v.styles.Box.Copy().
			BorderForeground(lipgloss.Color("#444444")). // Subtle gray border
			MarginTop(1).
			Width(60).
			Align(lipgloss.Left).
			Render(
				lipgloss.JoinVertical(
					lipgloss.Left,
					v.styles.DialogText.Bold(true).Foreground(lipgloss.Color("#00ff00")).Render("Interface Details"),
					"",
					lipgloss.JoinHorizontal(
						lipgloss.Left,
						v.styles.DialogText.Copy().Width(14).Align(lipgloss.Right).Foreground(lipgloss.Color("#00ff00")).Render("Name"),
						"  ",
						v.styles.DialogText.Copy().Foreground(lipgloss.Color("#FFFFFF")).Render(nameDisplay),
					),
					lipgloss.JoinHorizontal(
						lipgloss.Left,
						v.styles.DialogText.Copy().Width(14).Align(lipgloss.Right).Foreground(lipgloss.Color("#00ff00")).Render("IP Address"),
						"  ",
						v.styles.DialogText.Copy().Foreground(lipgloss.Color("#FFFFFF")).Render(fmt.Sprintf("%s%s", selected.IPAddress, selected.CIDR)),
					),
					lipgloss.JoinHorizontal(
						lipgloss.Left,
						v.styles.DialogText.Copy().Width(14).Align(lipgloss.Right).Foreground(lipgloss.Color("#00ff00")).Render("Gateway"),
						"  ",
						v.styles.DialogText.Copy().Foreground(lipgloss.Color("#FFFFFF")).Render(selected.Gateway),
					),
					lipgloss.JoinHorizontal(
						lipgloss.Left,
						v.styles.DialogText.Copy().Width(14).Align(lipgloss.Right).Foreground(lipgloss.Color("#00ff00")).Render("MAC Address"),
						"  ",
						v.styles.DialogText.Copy().Foreground(lipgloss.Color("#FFFFFF")).Render(selected.MACAddress),
					),
					lipgloss.JoinHorizontal(
						lipgloss.Left,
						v.styles.DialogText.Copy().Width(14).Align(lipgloss.Right).Foreground(lipgloss.Color("#00ff00")).Render("Subnet Mask"),
						"  ",
						v.styles.DialogText.Copy().Foreground(lipgloss.Color("#FFFFFF")).Render(selected.SubnetMask),
					),
					lipgloss.JoinHorizontal(
						lipgloss.Left,
						v.styles.DialogText.Copy().Width(14).Align(lipgloss.Right).Foreground(lipgloss.Color("#00ff00")).Render("Status"),
						"  ",
						v.styles.DialogText.Copy().Foreground(lipgloss.Color("#FFFFFF")).Render(map[bool]string{true: "UP", false: "DOWN"}[selected.IsUp]),
					),
				),
			)
	}

	// Create help text
	help := v.styles.Help.Render("↑↓ Select • Enter Confirm")

	// Combine all elements with proper spacing
	content := lipgloss.JoinVertical(
		lipgloss.Center,
		banner,
		//"\n",
		title,
		//"\n",
		list,
		details,
		//"\n",
		help,
	)

	return lipgloss.Place(
		v.width,
		v.height,
		lipgloss.Center,
		lipgloss.Center,
		content,
	)
}
