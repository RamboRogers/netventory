package views

import (
	"runtime"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// WelcomeView handles the welcome screen
type WelcomeView struct {
	styles  *Styles
	width   int
	height  int
	frame   int
	version string
}

// NewWelcomeView creates a new welcome view
func NewWelcomeView(styles *Styles, version string) *WelcomeView {
	return &WelcomeView{
		styles:  styles,
		version: version,
	}
}

// SetDimensions updates the view dimensions
func (v *WelcomeView) SetDimensions(width, height int) {
	v.width = width
	v.height = height
}

// SetFrame updates the animation frame
func (v *WelcomeView) SetFrame(frame int) {
	v.frame = frame
}

// Render generates the view
func (v *WelcomeView) Render() string {
	// Create banner
	banner := v.styles.RenderBanner()

	// Render the scanner
	scanner := v.renderScanner()

	// Create the system info block
	sysInfo := []string{
		v.formatInfoLine("Version", v.version, false),
		v.formatInfoLine("OS", runtime.GOOS, false),
		v.formatInfoLine("Architecture", runtime.GOARCH, true),
	}

	infoBox := v.styles.Box.Padding(0, 1).Align(lipgloss.Center).Render(strings.Join(sysInfo, "\n"))

	// Combine all blocks
	content := lipgloss.JoinVertical(
		lipgloss.Center,
		banner,
		"\n",
		scanner,
		"\n",
		infoBox,
	)

	// Calculate vertical padding
	contentHeight := strings.Count(content, "\n") + 1
	topPadding := (v.height - contentHeight) / 2
	if topPadding < 0 {
		topPadding = 0
	}

	return lipgloss.Place(
		v.width,
		v.height,
		lipgloss.Center,
		lipgloss.Center,
		content,
	)
}

// Helper function to format info lines with consistent labels
func (v *WelcomeView) formatInfoLine(label, value string, isLastLine bool) string {
	labelWidth := 15 // Adjust this width to fit the longest label
	valueWidth := 10 // Adjust this width to fit the longest value

	// Truncate or pad the value to fit within the valueWidth
	if len(value) > valueWidth {
		value = value[:valueWidth]
	} else {
		value = value + strings.Repeat(" ", valueWidth-len(value))
	}

	paddedLabel := lipgloss.NewStyle().
		Foreground(lipgloss.Color("10")).
		Align(lipgloss.Right).
		Width(labelWidth).
		Render(label + ":")

	paddedValue := lipgloss.NewStyle().
		Foreground(lipgloss.Color("15")).
		Align(lipgloss.Left).
		Width(valueWidth).
		Render(value)

	// Add a blank row at the end if it's the last line
	result := lipgloss.JoinHorizontal(lipgloss.Left, paddedLabel, " ", paddedValue)
	if isLastLine {
		result += "\n"
	}

	return result
}

// renderScanner creates the animated scanner display
func (v *WelcomeView) renderScanner() string {
	// Create a full bar with rolling brightness
	var coloredParts []string
	barWidth := 24
	peakPos := v.frame % barWidth

	for i := 0; i < barWidth; i++ {
		dist := abs(i - peakPos)
		if dist > barWidth/2 {
			dist = barWidth - dist
		}
		colorIndex := dist % len(scanColors)
		style := lipgloss.NewStyle().Foreground(scanColors[colorIndex])
		coloredParts = append(coloredParts, style.Render("█"))
	}

	return v.styles.Box.Copy().
		Width(56).
		Padding(0, 1).
		Align(lipgloss.Center).
		Render(
			v.styles.DialogText.Bold(true).Render("Network Scanner") + "\n" +
				strings.Join(coloredParts, ""),
		)
}

// abs returns the absolute value of x
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
