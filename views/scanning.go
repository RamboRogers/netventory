package views

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/lipgloss"
	"github.com/ramborogers/netventory/scanner"
)

// ScanningView handles the network scanning screen
type ScanningView struct {
	styles         *Styles
	width          int
	height         int
	devices        map[string]scanner.Device
	selectedIndex  int
	tableOffset    int
	showingDetails bool
	scanningActive bool
	currentIP      string
	scanStartTime  time.Time
	workerStats    map[int]*scanner.WorkerStatus
	statsLock      sync.RWMutex
	table          table.Model
	finalProgress  float64
	finalScanned   int32
	finalTotal     int32
	finalElapsed   time.Duration
}

// NewScanningView creates a new scanning view
func NewScanningView(styles *Styles) *ScanningView {
	return &ScanningView{
		styles:      styles,
		devices:     make(map[string]scanner.Device),
		workerStats: make(map[int]*scanner.WorkerStatus),
	}
}

// SetDimensions updates the view dimensions
func (v *ScanningView) SetDimensions(width, height int) {
	v.width = width
	v.height = height
}

// SetDevices updates the list of discovered devices
func (v *ScanningView) SetDevices(devices map[string]scanner.Device) {
	v.devices = devices
}

// SetSelectedIndex updates the selected device index
func (v *ScanningView) SetSelectedIndex(index int) {
	v.selectedIndex = index
}

// SetTableOffset updates the table scroll offset
func (v *ScanningView) SetTableOffset(offset int) {
	v.tableOffset = offset
}

// SetShowingDetails updates whether device details are being shown
func (v *ScanningView) SetShowingDetails(showing bool) {
	v.showingDetails = showing
}

// SetScanningActive updates whether scanning is active
func (v *ScanningView) SetScanningActive(active bool) {
	if v.scanningActive && !active {
		// Capture final values when scan completes
		v.statsLock.RLock()
		for _, stat := range v.workerStats {
			v.finalScanned = stat.IPsScanned
			v.finalTotal = stat.TotalIPs
			if v.finalTotal > 0 {
				v.finalProgress = float64(v.finalScanned) / float64(v.finalTotal) * 100
				if v.finalProgress > 100.0 {
					v.finalProgress = 100.0
				}
			}
			break
		}
		v.statsLock.RUnlock()

		// If we didn't get final values from worker stats, try to count devices
		if v.finalScanned == 0 {
			v.finalScanned = int32(len(v.devices))
			if v.finalTotal > 0 {
				v.finalProgress = float64(v.finalScanned) / float64(v.finalTotal) * 100
				if v.finalProgress > 100.0 {
					v.finalProgress = 100.0
				}
			}
		}

		// Store final elapsed time
		v.finalElapsed = time.Since(v.scanStartTime).Round(time.Second)
	} else if active {
		// Reset all view state when starting a new scan
		v.finalProgress = 0
		v.finalScanned = 0
		v.finalTotal = 0
		v.finalElapsed = 0
		v.currentIP = ""
		v.tableOffset = 0
		v.selectedIndex = 0

		// Clear worker stats
		v.statsLock.Lock()
		v.workerStats = make(map[int]*scanner.WorkerStatus)
		v.statsLock.Unlock()

		// Reset table
		v.table = table.Model{}
	}
	v.scanningActive = active
}

// SetCurrentIP updates the current IP being scanned
func (v *ScanningView) SetCurrentIP(ip string) {
	v.currentIP = ip
}

// SetProgress updates the scan progress
func (v *ScanningView) SetProgress(scanned, total, discovered int32) {
	// We don't need to store these anymore as we'll get them from worker stats
	// But if we're not scanning and don't have final values, use these
	if !v.scanningActive && v.finalScanned == 0 {
		v.finalScanned = scanned
		v.finalTotal = total
		if total > 0 {
			v.finalProgress = float64(scanned) / float64(total) * 100
		}
	}
}

// SetScanStartTime updates the scan start time
func (v *ScanningView) SetScanStartTime(t time.Time) {
	v.scanStartTime = t
}

// SetWorkerStats updates the worker statistics
func (v *ScanningView) SetWorkerStats(stats map[int]*scanner.WorkerStatus) {
	v.statsLock.Lock()
	v.workerStats = stats
	v.statsLock.Unlock()
}

// GetSelectedDevice returns the currently selected device
func (v *ScanningView) GetSelectedDevice() (scanner.Device, bool) {
	if len(v.devices) == 0 {
		return scanner.Device{}, false
	}

	// Get sorted list of IPs
	var ips []string
	for ip := range v.devices {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIPs(ips[i], ips[j])
	})

	// Ensure selected index is valid
	if v.selectedIndex >= 0 && v.selectedIndex < len(ips) {
		return v.devices[ips[v.selectedIndex]], true
	}

	return scanner.Device{}, false
}

// Render generates the view
func (v *ScanningView) Render() string {
	// Create progress bar
	var progress float64
	var displayScanned, displaySent, displayTotal int32
	var activeWorkers int
	totalFound := len(v.devices)

	if !v.scanningActive && v.finalScanned > 0 {
		// Use final values when scan is complete
		progress = v.finalProgress
		displayScanned = v.finalScanned
		displayTotal = v.finalTotal
		displaySent = displayTotal // When complete, all IPs were sent
		activeWorkers = 0
	} else {
		// Get current stats from workers
		v.statsLock.RLock()
		var lastStat *scanner.WorkerStatus

		// Get stats from any worker to get the global counts
		for _, stat := range v.workerStats {
			if time.Since(stat.LastSeen) < time.Second*2 {
				activeWorkers++
			}
			lastStat = stat // Keep track of last stat for totals
		}

		if lastStat != nil {
			displayTotal = lastStat.TotalIPs
			displayScanned = lastStat.IPsScanned
			displaySent = lastStat.SentCount
		} else if totalFound > 0 {
			// If we have devices but no workers, we're done
			displayTotal = int32(totalFound)
			displayScanned = displayTotal
			displaySent = displayTotal
			progress = 100.0
		}
		v.statsLock.RUnlock()

		// Calculate progress based on completed IPs vs total
		if displayTotal > 0 {
			progress = float64(displayScanned) / float64(displayTotal) * 100
			if progress > 100.0 {
				progress = 100.0
			}
		}
	}

	progressWidth := 48
	filledWidth := int(float64(progressWidth) * progress / 100)

	var progressBar strings.Builder
	progressBar.WriteString("[")
	for i := 0; i < progressWidth; i++ {
		if i < filledWidth {
			progressBar.WriteString(lipgloss.NewStyle().Foreground(primaryColor).Render("█"))
		} else {
			progressBar.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("#333333")).Render("█"))
		}
	}
	progressBar.WriteString("]")

	// Format elapsed time
	var elapsed time.Duration
	if !v.scanningActive && activeWorkers == 0 {
		elapsed = v.finalElapsed
	} else {
		elapsed = time.Since(v.scanStartTime).Round(time.Second)
	}
	var rate float64
	if elapsed.Seconds() > 0 {
		rate = float64(displayScanned) / elapsed.Seconds()
	}

	// Create centered progress info without any containing box
	progressInfo := lipgloss.NewStyle().
		Width(v.width).
		Align(lipgloss.Center).
		Render(progressBar.String())

	// Show both completed and queued IPs in stats
	statsText := lipgloss.NewStyle().
		Width(v.width).
		Align(lipgloss.Center).
		Render(fmt.Sprintf(
			"Progress: %.1f%% (%d/%d) | Queued: %d | Rate: %.1f/sec",
			progress,
			min32(displayScanned, displayTotal),
			displayTotal,
			max32(0, displaySent-displayScanned),
			rate,
		))

	// Show more detailed stats with completion status
	var statusText string
	if !v.scanningActive && activeWorkers == 0 {
		statusText = "Scan Done"
	} else {
		statusText = fmt.Sprintf("Active Workers: %d", activeWorkers)
	}

	foundText := lipgloss.NewStyle().
		Width(v.width).
		Align(lipgloss.Center).
		Render(fmt.Sprintf(
			"Found: %d devices | %s | Time: %v",
			totalFound,
			statusText,
			elapsed,
		))

	brandingText := lipgloss.NewStyle().
		Width(v.width).
		Align(lipgloss.Center).
		Render("⎯ NetVentory ⎯")

	// Join stats vertically
	statsInfo := lipgloss.JoinVertical(
		lipgloss.Center,
		brandingText,
		progressInfo,
		statsText,
		foundText,
	)

	// Calculate available height for table
	// Reserve space for stats(4), margins(4), and help(3)
	reservedHeight := 14
	availableHeight := v.height - reservedHeight
	// Limit table to maximum of 10 rows, regardless of screen size
	visibleRows := min(availableHeight, len(v.devices))

	// Create table data with scrolling
	var rows []table.Row
	var ips []string
	for ip := range v.devices {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return compareIPs(ips[i], ips[j])
	})

	// Calculate visible range
	startIdx := v.tableOffset
	endIdx := min(startIdx+visibleRows, len(ips))

	// Create rows for visible devices
	for _, ip := range ips[startIdx:endIdx] {
		device := v.devices[ip]
		hostname := "N/A"
		if len(device.Hostname) > 0 {
			hostname = truncate(device.Hostname[0], 40)
		}

		// Format status with mDNS indicator if applicable
		status := device.Status
		if device.MDNSName != "" || len(device.MDNSServices) > 0 {
			status += ",mDNS"
		}

		rows = append(rows, table.Row{
			device.IPAddress,
			hostname,
			status,
		})
	}

	// Configure table with fixed widths
	columns := []table.Column{
		{Title: "IP Address", Width: 15},
		{Title: "Hostname", Width: 42},
		{Title: "Status", Width: 15},
	}

	// Enhanced selected row style
	tableStyle := table.Styles{
		Header: lipgloss.NewStyle().
			Bold(true).
			Foreground(primaryColor).
			Align(lipgloss.Left),
		Selected: lipgloss.NewStyle().
			Background(primaryColor).
			Foreground(lipgloss.Color("#000000")). // Black text on green background
			Bold(true).
			Align(lipgloss.Left),
		Cell: lipgloss.NewStyle().
			Foreground(secondaryColor).
			Align(lipgloss.Left),
	}

	t := table.New(
		table.WithColumns(columns),
		table.WithRows(rows),
		table.WithFocused(true),
		table.WithHeight(visibleRows),
		table.WithStyles(tableStyle),
	)

	// Update selected row - fix the cursor position calculation
	if len(rows) > 0 {
		cursorPos := v.selectedIndex - v.tableOffset
		if cursorPos >= 0 && cursorPos < len(rows) {
			t.SetCursor(cursorPos)
		}
	}

	v.table = t

	// Calculate if scrolling is possible
	totalDevices := len(v.devices)
	hasMoreAbove := v.tableOffset > 0
	hasMoreBelow := v.tableOffset+visibleRows < totalDevices

	// Add scroll indicators to table
	tableView := v.table.View()
	if hasMoreAbove {
		tableView = v.styles.DialogText.Foreground(primaryColor).SetString("▲").String() + "\n" + tableView
	}
	if hasMoreBelow {
		tableView = tableView + "\n" + v.styles.DialogText.Foreground(primaryColor).SetString("▼").String()
	}

	// Update help text based on state
	var helpText string
	if v.scanningActive {
		helpText = "↑↓ Select • Enter Details • s Stop Scan • q Quit"
	} else {
		if totalDevices > visibleRows {
			helpText = "↑↓ Scroll • PgUp/PgDn Jump • Enter Details • r Rescan • q Quit"
		} else {
			helpText = "↑↓ Select • Enter Details • r Rescan • q Quit"
		}
	}

	// Create help box that will be placed at the bottom
	helpBox := v.styles.Help.Copy().
		Width(v.width-4). // Account for margins
		Padding(0, 1).
		Render(helpText)

	// Create the main layout
	mainLayout := lipgloss.JoinVertical(
		lipgloss.Center,
		"\n", // Add some top spacing
		statsInfo,
		"\n",
		tableView,
	)

	// Place the main layout in the content area
	mainView := lipgloss.Place(
		v.width,
		v.height-3, // Reserve space for help box
		lipgloss.Center,
		lipgloss.Top,
		mainLayout,
	)

	// Return the final view
	return lipgloss.JoinVertical(
		lipgloss.Top,
		mainView,
		helpBox,
	)
}

// Helper functions
func truncate(s string, length int) string {
	if len(s) <= length {
		return s
	}
	return s[:length-3] + "..."
}

func compareIPs(a, b string) bool {
	aOctets := strings.Split(a, ".")
	bOctets := strings.Split(b, ".")

	for i := 0; i < 4; i++ {
		aNum, _ := strconv.Atoi(aOctets[i])
		bNum, _ := strconv.Atoi(bOctets[i])
		if aNum != bNum {
			return aNum < bNum
		}
	}
	return false
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Helper function to get minimum of two int32s
func min32(a, b int32) int32 {
	if a < b {
		return a
	}
	return b
}

// Helper function to get maximum of two int32s
func max32(a, b int32) int32 {
	if a > b {
		return a
	}
	return b
}
