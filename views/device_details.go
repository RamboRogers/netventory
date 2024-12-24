package views

import (
	"fmt"
	"sort"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/ramborogers/netventory/scanner"
)

// DeviceDetailsView handles the device details screen
type DeviceDetailsView struct {
	styles *Styles
	width  int
	height int
	device scanner.Device
}

// NewDeviceDetailsView creates a new device details view
func NewDeviceDetailsView(styles *Styles) *DeviceDetailsView {
	return &DeviceDetailsView{
		styles: styles,
	}
}

// SetDimensions updates the view dimensions
func (v *DeviceDetailsView) SetDimensions(width, height int) {
	v.width = width
	v.height = height
}

// SetDevice updates the device being displayed
func (v *DeviceDetailsView) SetDevice(device scanner.Device) {
	v.device = device
}

// formatPortURL returns a properly formatted URL for a given port
func (v *DeviceDetailsView) formatPortURL(port int) string {
	switch port {
	case 80:
		return fmt.Sprintf("http://%s", v.device.IPAddress)
	case 445:
		return fmt.Sprintf("smb://%s", v.device.IPAddress)
	case 443, 8443:
		return fmt.Sprintf("https://%s", v.device.IPAddress)
	case 8080:
		return fmt.Sprintf("http://%s:8080", v.device.IPAddress)
	case 21:
		return fmt.Sprintf("ftp://%s", v.device.IPAddress)
	case 22:
		return fmt.Sprintf("ssh://%s", v.device.IPAddress)
	case 3389:
		return fmt.Sprintf("rdp://%s", v.device.IPAddress)
	case 5900:
		return fmt.Sprintf("vnc://%s", v.device.IPAddress)
	default:
		return fmt.Sprintf("http://%s:%d", v.device.IPAddress, port)
	}
}

// Render generates the view
func (v *DeviceDetailsView) Render() string {
	var content strings.Builder

	// Section headers style
	headerStyle := v.styles.DialogText.Copy().
		Bold(true).
		Align(lipgloss.Center).
		Foreground(lipgloss.Color("#00ff00"))

	// Label style (right-aligned, fixed width)
	labelStyle := v.styles.DialogText.Copy().
		Width(12).
		Align(lipgloss.Right).
		Foreground(lipgloss.Color("#00ff00"))

	// Value style (right-aligned)
	valueStyle := v.styles.DialogText.Copy().
		Width(30).
		Align(lipgloss.Right).
		Foreground(lipgloss.Color("#FFFFFF"))

	// Network Information section
	content.WriteString(headerStyle.Render("Network Information"))
	content.WriteString("\n\n")

	// IP Address row
	content.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Right,
		labelStyle.Align(lipgloss.Right).Render("IP Address"),
		valueStyle.Align(lipgloss.Left).Render(v.device.IPAddress),
	))
	content.WriteString("\n")

	// MAC Address row
	macAddress := "Unknown"
	if v.device.MACAddress != "" {
		macAddress = v.device.MACAddress
	}
	content.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Right,
		labelStyle.Align(lipgloss.Right).Render("MAC"),
		valueStyle.Align(lipgloss.Left).Render(macAddress),
	))
	content.WriteString("\n")

	// mDNS Name row
	if v.device.MDNSName != "" {
		content.WriteString(lipgloss.JoinHorizontal(
			lipgloss.Right,
			labelStyle.Align(lipgloss.Right).Render("mDNS Name"),
			valueStyle.Align(lipgloss.Left).Render(v.device.MDNSName),
		))
		content.WriteString("\n")
	}

	// Hostname row
	if len(v.device.Hostname) > 0 {
		content.WriteString(lipgloss.JoinHorizontal(
			lipgloss.Right,
			labelStyle.Align(lipgloss.Right).Render("Hostname"),
			valueStyle.Align(lipgloss.Left).Render(strings.Join(v.device.Hostname, ", ")),
		))
		content.WriteString("\n")
	}

	// Status Information section
	content.WriteString("\n")
	content.WriteString(headerStyle.Render("Status Information"))
	content.WriteString("\n\n")

	// Status row
	content.WriteString(lipgloss.JoinHorizontal(
		lipgloss.Left,
		labelStyle.Align(lipgloss.Right).Render("Status"),
		valueStyle.Align(lipgloss.Left).Render(v.device.Status),
	))

	// Open Ports section
	if len(v.device.OpenPorts) > 0 {
		content.WriteString("\n\n")
		content.WriteString(headerStyle.Render("Open Ports"))
		content.WriteString("\n\n")

		// Sort ports for consistent display
		ports := make([]int, len(v.device.OpenPorts))
		copy(ports, v.device.OpenPorts)
		sort.Ints(ports)

		// Port label style (includes "Port" prefix)
		portLabelStyle := v.styles.DialogText.Copy().
			Width(11).
			Align(lipgloss.Right).
			Foreground(lipgloss.Color("#00ff00"))

		// URL value style with fixed width for alignment
		urlStyle := v.styles.DialogText.Copy().
			Width(30).
			Align(lipgloss.Left).
			Foreground(lipgloss.Color("#FFFFFF"))

		// Display each port with its URL
		for _, port := range ports {
			content.WriteString(lipgloss.JoinHorizontal(
				lipgloss.Left,
				portLabelStyle.Render(fmt.Sprintf("Port %d", port)),
				"  ",
				urlStyle.Render(v.formatPortURL(port)),
			))
			content.WriteString("\n")
		}
	}

	// mDNS Services section
	if len(v.device.MDNSServices) > 0 {
		content.WriteString("\n\n")
		content.WriteString(headerStyle.Render("mDNS Services"))
		content.WriteString("\n\n")

		// Service value style
		serviceStyle := v.styles.DialogText.Copy().
			Align(lipgloss.Left).
			Foreground(lipgloss.Color("#FFFFFF"))

		// Display each service
		for _, service := range v.device.MDNSServices {
			content.WriteString(serviceStyle.Render(service))
			content.WriteString("\n")
		}
	}

	// Help text in a box
	helpBox := v.styles.Box.Copy().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#00ff00")).
		Width(40).
		Align(lipgloss.Center).
		Margin(1, 0).
		Padding(1, 2).
		Render("Enter/Return to go back")

	// Combine content and help box
	finalContent := lipgloss.JoinVertical(
		lipgloss.Center,
		v.styles.DialogBox.Render(content.String()),
		helpBox,
	)

	// Place everything in the center of the screen
	return lipgloss.Place(
		v.width,
		v.height,
		lipgloss.Center,
		lipgloss.Center,
		finalContent,
	)
}
