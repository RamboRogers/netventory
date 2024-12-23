package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/jackpal/gateway"
	"github.com/mattbnz/netventory/scanner"
	"github.com/mattbnz/netventory/views"
)

const (
	version = "0.1.0"
	debug   = false // Default debug setting, can be overridden by -debug flag
)

var (
	workerCount = 50 // Default worker count, can be overridden by -w flag
)

func init() {
	// Parse command line flags
	debugFlag := flag.Bool("debug", debug, "Enable debug mode (generates debug.log and report.log in current directory)")
	workers := flag.Int("w", workerCount, "Number of concurrent scanning workers (default: 50)")
	versionFlag := flag.Bool("version", false, "Display version information and exit")

	// Add help text
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "netventory %s - Network Discovery Tool by RamboRogers\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	flag.Parse()

	// Handle version flag first
	if *versionFlag {
		fmt.Printf("netventory %s\n", version)
		os.Exit(0)
	}

	// Show help if any non-flag arguments are provided
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "Error: unexpected argument '%s'\n\n", flag.Arg(0))
		flag.Usage()
	}

	// Update global settings from flags
	if *debugFlag {
		// Set up logging to file if debug is enabled
		f, err := os.OpenFile("debug.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening debug.log: %v", err)
		}
		log.SetOutput(f)
	} else {
		// Disable logging when debug is false
		log.SetOutput(io.Discard)
	}

	if *workers > 0 {
		workerCount = *workers
	}
}

// Model represents the application state
type Model struct {
	currentScreen     string
	interfaces        []views.Interface
	selectedIndex     int
	err               error
	width             int
	height            int
	frame             int
	proposedRange     string
	editingRange      bool
	cursorPos         int
	devices           map[string]scanner.Device
	scanningActive    bool
	currentIP         string
	scanSelectedIndex int
	showingDetails    bool
	activeScans       map[string]bool
	deviceMutex       sync.RWMutex
	tableOffset       int
	totalIPs          int32
	scannedCount      int32
	discoveredCount   int32
	scanStartTime     time.Time
	workerStats       map[int]*scanner.WorkerStatus
	statsLock         sync.RWMutex
	scanner           *scanner.Scanner
	styles            *views.Styles
	welcomeView       *views.WelcomeView
	interfacesView    *views.InterfacesView
	confirmView       *views.ConfirmView
	scanningView      *views.ScanningView
	deviceDetailsView *views.DeviceDetailsView
}

// Add constants for screen states
const (
	screenWelcome    = "welcome"
	screenInterfaces = "interfaces"
	screenConfirm    = "confirm"
	screenScanning   = "scanning"
	screenResults    = "results"
)

// Add message types
type interfacesMsg []views.Interface
type errMsg struct{ error }
type deviceMsg struct {
	done bool
}

// Add DeviceUpdate type definition near other types at the top
type DeviceUpdate struct {
	Device scanner.Device
}

// Add new message type for scan updates
type scanUpdateMsg struct {
	device       scanner.Device
	totalHosts   int
	scannedHosts int
}

// Add new message type for stats updates
type statsUpdateMsg struct{}

// Add stats ticker command
func statsTick() tea.Cmd {
	return tea.Tick(time.Millisecond*200, func(t time.Time) tea.Msg {
		return statsUpdateMsg{}
	})
}

// Add new message type for welcome timer
type welcomeTimerMsg struct{}

// Add welcome timer command
func welcomeTimer() tea.Cmd {
	return tea.Tick(900*time.Millisecond, func(t time.Time) tea.Msg {
		return welcomeTimerMsg{}
	})
}

// Update initialModel to start the welcome timer
func initialModel() *Model {
	styles := views.NewStyles()

	m := &Model{
		currentScreen:     screenWelcome,
		devices:           make(map[string]scanner.Device),
		activeScans:       make(map[string]bool),
		workerStats:       make(map[int]*scanner.WorkerStatus),
		selectedIndex:     0,
		scanSelectedIndex: 0,
		tableOffset:       0,
		showingDetails:    false,
		editingRange:      false,
		cursorPos:         0,
		frame:             0,
		scanningActive:    false,
		currentIP:         "",
		styles:            styles,
		welcomeView:       views.NewWelcomeView(styles, version),
		interfacesView:    views.NewInterfacesView(styles),
		confirmView:       views.NewConfirmView(styles),
		scanningView:      views.NewScanningView(styles),
		deviceDetailsView: views.NewDeviceDetailsView(styles),
	}

	return m
}

// Define a command that reads exactly one result from resultsChan or doneChan.
// We'll call this each time we handle scanUpdateMsg so it keeps pulling messages until the channel is closed.
func (m *Model) readScanResultCmd() tea.Cmd {
	return func() tea.Msg {
		if m.scanner == nil {
			return deviceMsg{done: true}
		}

		resultsChan, doneChan := m.scanner.GetResults()
		select {
		case device, ok := <-resultsChan:
			if !ok {
				// resultsChan was closed
				log.Printf("Results channel closed")
				return deviceMsg{done: true}
			}
			log.Printf("Received device: %s", device.IPAddress)

			// Get latest stats from scanner
			stats := m.scanner.GetWorkerStats()
			var totalScanned int32
			for _, stat := range stats {
				totalScanned += atomic.LoadInt32(&stat.IPsScanned)
			}

			// Return a scanUpdateMsg with latest stats
			return scanUpdateMsg{
				device:       device,
				totalHosts:   int(atomic.LoadInt32(&m.totalIPs)),
				scannedHosts: int(totalScanned),
			}

		case <-doneChan:
			// The scanning goroutines have signaled completion
			log.Printf("Scan complete - closing scanner")
			m.scanner.Close() // Close the scanner and its report file
			m.scanningActive = false
			return deviceMsg{done: true}

		default:
			// No update available, check again soon
			time.Sleep(100 * time.Millisecond)
			return scanUpdateMsg{} // Empty update to keep the UI refreshing
		}
	}
}

// Improved scanning pipeline
func (m *Model) scanNetwork(cidr string) tea.Cmd {
	return func() tea.Msg {
		log.Printf("=== Starting new scan ===")
		log.Printf("CIDR Range: %s", cidr)

		// Create new scanner instance
		m.scanner = scanner.NewScanner(debug)
		if m.scanner == nil {
			return errMsg{fmt.Errorf("failed to create scanner")}
		}

		// Reset scan state
		m.deviceMutex.Lock()
		m.devices = make(map[string]scanner.Device)
		m.deviceMutex.Unlock()

		// Reset worker stats
		m.statsLock.Lock()
		m.workerStats = make(map[int]*scanner.WorkerStatus)
		m.statsLock.Unlock()

		// Parse CIDR to get total IPs for progress tracking
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return errMsg{err}
		}
		ips := scanner.GetAllIPs(ipNet)
		atomic.StoreInt32(&m.totalIPs, int32(len(ips)))
		atomic.StoreInt32(&m.scannedCount, 0)
		atomic.StoreInt32(&m.discoveredCount, 0)
		m.scanStartTime = time.Now()
		m.scanningActive = true

		// Set scan start time in the scanning view
		m.scanningView.SetScanStartTime(m.scanStartTime)

		// Start the scan
		if err := m.scanner.ScanNetwork(cidr, workerCount); err != nil {
			return errMsg{err}
		}

		// Return both commands
		return tea.Batch(
			m.readScanResultCmd(),
			statsTick(),
		)()
	}
}

// Update animation speed
func tick() tea.Cmd {
	return tea.Tick(time.Millisecond*80, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Add tick message type
type tickMsg time.Time

// Init implements tea.Model
func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		welcomeTimer(),
		func() tea.Msg {
			interfaces, err := getNetworkInterfaces()
			if err != nil {
				return errMsg{err}
			}
			return interfacesMsg(interfaces)
		},
	)
}

// Update implements tea.Model
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case welcomeTimerMsg:
		if m.currentScreen == screenWelcome {
			m.currentScreen = screenInterfaces
		}
		return m, nil
	case tickMsg:
		m.frame++ // Increment frame counter for animation
		return m, tick()
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil
	case interfacesMsg:
		m.interfaces = msg
		return m, nil
	case errMsg:
		m.err = msg
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c":
			return m, tea.Quit
		case "q":
			if !m.showingDetails && (m.currentScreen == screenScanning || m.currentScreen == screenResults) {
				return m, tea.Quit
			}
		case "e":
			if m.currentScreen == screenConfirm {
				m.editingRange = true
			}
		case "up", "k":
			if m.currentScreen == screenScanning || m.currentScreen == screenResults {
				if m.scanSelectedIndex > 0 {
					m.scanSelectedIndex--
					if m.scanSelectedIndex < m.tableOffset {
						m.tableOffset = m.scanSelectedIndex
					}
				}
			} else if m.selectedIndex > 0 {
				m.selectedIndex--
			}
		case "down", "j":
			if m.currentScreen == screenScanning || m.currentScreen == screenResults {
				deviceCount := len(m.devices)
				if m.scanSelectedIndex < deviceCount-1 {
					m.scanSelectedIndex++
					if m.scanSelectedIndex >= m.tableOffset+10 {
						m.tableOffset = m.scanSelectedIndex - 9
					}
				}
			} else if m.selectedIndex < len(m.interfaces)-1 {
				m.selectedIndex++
			}
		case "pgup":
			if m.currentScreen == screenScanning || m.currentScreen == screenResults {
				m.tableOffset = max(0, m.tableOffset-10)
				m.scanSelectedIndex = max(m.scanSelectedIndex-10, m.tableOffset)
			}
		case "pgdown":
			if m.currentScreen == screenScanning || m.currentScreen == screenResults {
				deviceCount := len(m.devices)
				maxOffset := max(0, deviceCount-10)
				m.tableOffset = min(maxOffset, m.tableOffset+10)
				m.scanSelectedIndex = min(m.scanSelectedIndex+10, deviceCount-1)
			}
		case "s":
			if m.currentScreen == screenScanning && m.scanningActive {
				m.scanner.Stop() // Actually stop the scanner
				m.scanningActive = false
				m.currentScreen = screenResults
			}
		case "r":
			if m.currentScreen == screenResults {
				m.currentScreen = screenScanning
				m.scanningActive = true
				return m, tea.Batch(
					m.scanNetwork(m.proposedRange),
					tick(),
				)
			}
		case "enter":
			switch m.currentScreen {
			case screenWelcome:
				m.currentScreen = screenInterfaces
			case screenInterfaces:
				if len(m.interfaces) > 0 {
					selected := m.interfaces[m.selectedIndex]
					m.proposedRange = calculateNetworkRange(selected.IPAddress, selected.CIDR)
					m.currentScreen = screenConfirm
					m.editingRange = false
					m.cursorPos = len(m.proposedRange)
				}
			case screenConfirm:
				if m.editingRange {
					m.editingRange = false
				} else {
					m.currentScreen = screenScanning
					m.scanningActive = true
					return m, tea.Batch(
						m.scanNetwork(m.proposedRange),
						tick(),
					)
				}
			case screenScanning, screenResults:
				if device, ok := m.scanningView.GetSelectedDevice(); ok {
					m.showingDetails = !m.showingDetails
					if m.showingDetails {
						m.deviceDetailsView.SetDevice(device)
						m.deviceDetailsView.SetDimensions(m.width, m.height)
					}
				}
			}
		case "esc":
			if m.currentScreen == screenConfirm {
				if m.editingRange {
					m.editingRange = false
				} else {
					m.currentScreen = screenInterfaces
				}
			} else if m.showingDetails {
				m.showingDetails = false
			}
		// Add editing controls when editing range
		case "left":
			if m.editingRange && m.cursorPos > 0 {
				m.cursorPos--
			}
		case "right":
			if m.editingRange && m.cursorPos < len(m.proposedRange) {
				m.cursorPos++
			}
		case "backspace":
			if m.editingRange && m.cursorPos > 0 {
				m.proposedRange = m.proposedRange[:m.cursorPos-1] + m.proposedRange[m.cursorPos:]
				m.cursorPos--
			}
		default:
			if m.editingRange {
				// Only allow numbers, dots, and forward slash
				if matched, _ := regexp.MatchString(`^[0-9./]$`, msg.String()); matched {
					m.proposedRange = m.proposedRange[:m.cursorPos] + msg.String() + m.proposedRange[m.cursorPos:]
					m.cursorPos++
				}
			}
		}
	case scanUpdateMsg:
		if msg.device.IPAddress != "" {
			m.deviceMutex.Lock()
			m.devices[msg.device.IPAddress] = msg.device
			m.deviceMutex.Unlock()
			atomic.AddInt32(&m.discoveredCount, 1)
		}

		// Update scan progress from scanner
		if m.scanner != nil {
			stats := m.scanner.GetWorkerStats()
			var totalScanned int32
			for _, stat := range stats {
				totalScanned += atomic.LoadInt32(&stat.IPsScanned)
			}
			atomic.StoreInt32(&m.scannedCount, totalScanned)

			// Update worker stats
			m.statsLock.Lock()
			m.workerStats = make(map[int]*scanner.WorkerStatus, len(stats))
			for id, stat := range stats {
				statCopy := stat // Create a copy of the stat
				m.workerStats[id] = &statCopy
			}
			m.statsLock.Unlock()

			// Update scanning view with latest stats
			m.scanningView.SetProgress(m.scannedCount, m.totalIPs, m.discoveredCount)
			m.scanningView.SetWorkerStats(m.workerStats)

			// Force a refresh of the view
			m.frame++ // Increment frame to trigger redraw
		}

		// Update current IP display
		m.currentIP = fmt.Sprintf("Scanning: %s (%d/%d)",
			msg.device.IPAddress,
			atomic.LoadInt32(&m.scannedCount),
			atomic.LoadInt32(&m.totalIPs),
		)

		// Return ourselves plus readScanResultCmd() again
		// so Bubble Tea keeps reading from resultsChan
		return m, tea.Batch(
			tick(),
			m.readScanResultCmd(),
		)
	case deviceMsg:
		if msg.done {
			m.scanningActive = false
			m.currentScreen = screenResults
			return m, nil
		}
		return m, nil
	case statsUpdateMsg:
		if m.scanningActive && m.scanner != nil {
			// Update scan progress from scanner
			stats := m.scanner.GetWorkerStats()
			var totalScanned int32
			for _, stat := range stats {
				totalScanned += atomic.LoadInt32(&stat.IPsScanned)
			}
			atomic.StoreInt32(&m.scannedCount, totalScanned)

			// Update worker stats
			m.statsLock.Lock()
			m.workerStats = make(map[int]*scanner.WorkerStatus, len(stats))
			for id, stat := range stats {
				statCopy := stat
				m.workerStats[id] = &statCopy
			}
			m.statsLock.Unlock()

			// Force a refresh of the view
			m.frame++

			// Continue stats updates while scanning
			return m, statsTick()
		}
		return m, nil
	}

	return m, tea.Batch(cmds...)
}

// Add helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Add calculateNetworkRange function
func calculateNetworkRange(ip string, cidr string) string {
	_, network, err := net.ParseCIDR(ip + cidr)
	if err != nil {
		return ip + cidr
	}
	return network.String()
}

// Add getNetworkInterfaces function
func getNetworkInterfaces() ([]views.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	// Get default gateway information
	gatewayIP, err := gateway.DiscoverGateway()
	if err != nil {
		log.Printf("Error discovering gateway: %v", err)
		gatewayIP = nil
	}

	var networkInterfaces []views.Interface
	for _, iface := range ifaces {
		// Handle interface flags based on OS
		isUp := iface.Flags&net.FlagUp != 0
		if runtime.GOOS == "windows" {
			// Windows might need additional checks
			isUp = isUp && iface.Flags&net.FlagBroadcast != 0
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Skip loopback and non-IPv4
			if ipNet.IP.IsLoopback() || ipNet.IP.To4() == nil {
				continue
			}

			// Get display name
			displayName := iface.Name
			if runtime.GOOS == "windows" {
				if friendly := getWindowsFriendlyName(iface.Name); friendly != "" {
					displayName = friendly
				}
			}

			// Determine gateway for this interface
			gateway := "Not detected"
			if gatewayIP != nil && ipNet.Contains(gatewayIP) {
				gateway = gatewayIP.String()
			}

			// Get subnet mask in CIDR notation
			ones, _ := ipNet.Mask.Size()
			cidr := fmt.Sprintf("/%d", ones)

			networkInterfaces = append(networkInterfaces, views.Interface{
				Name:         iface.Name,
				FriendlyName: displayName,
				IPAddress:    ipNet.IP.String(),
				SubnetMask:   ipNet.Mask.String(),
				CIDR:         cidr,
				MACAddress:   iface.HardwareAddr.String(),
				Gateway:      gateway,
				IsUp:         isUp,
				Priority:     getPriority(displayName), // Use display name for priority
			})
		}
	}

	// Sort interfaces by priority
	sort.Slice(networkInterfaces, func(i, j int) bool {
		return networkInterfaces[i].Priority < networkInterfaces[j].Priority
	})

	return networkInterfaces, nil
}

func getWindowsFriendlyName(interfaceName string) string {
	if runtime.GOOS != "windows" {
		return interfaceName
	}
	return interfaceName // Simplified for now
}

func getPriority(name string) int {
	switch {
	case strings.HasPrefix(name, "en"):
		return 1 // Ethernet/WiFi on macOS/BSD
	case strings.HasPrefix(name, "eth"):
		return 2 // Ethernet on Linux
	case strings.HasPrefix(name, "wlan"):
		return 3 // WiFi on Linux
	case strings.Contains(name, "Ethernet") || strings.Contains(name, "Local Area Connection"):
		return 2 // Ethernet on Windows
	case strings.Contains(name, "Wi-Fi") || strings.Contains(name, "Wireless"):
		return 3 // WiFi on Windows
	default:
		return 100 // Other interfaces
	}
}

// View implements tea.Model
func (m *Model) View() string {
	switch m.currentScreen {
	case screenWelcome:
		return m.renderWelcomeView()
	case screenInterfaces:
		return m.renderInterfacesView()
	case screenConfirm:
		return m.renderConfirmView()
	case screenScanning, screenResults:
		if m.showingDetails {
			m.deviceDetailsView.SetDimensions(m.width, m.height)
			return m.deviceDetailsView.Render()
		}
		return m.renderScanningView()
	default:
		return "Unknown screen"
	}
}

func (m *Model) renderWelcomeView() string {
	m.welcomeView.SetDimensions(m.width, m.height)
	m.welcomeView.SetFrame(m.frame)
	return m.welcomeView.Render()
}

func (m *Model) renderInterfacesView() string {
	m.interfacesView.SetDimensions(m.width, m.height)
	m.interfacesView.SetInterfaces(m.interfaces)
	m.interfacesView.SetSelectedIndex(m.selectedIndex)
	return m.interfacesView.Render()
}

func (m *Model) renderConfirmView() string {
	m.confirmView.SetDimensions(m.width, m.height)
	m.confirmView.SetInterface(m.interfaces[m.selectedIndex])
	m.confirmView.SetRange(m.proposedRange)
	m.confirmView.SetEditing(m.editingRange)
	m.confirmView.SetCursor(m.cursorPos)
	return m.confirmView.Render()
}

func (m *Model) renderScanningView() string {
	m.scanningView.SetDimensions(m.width, m.height)
	m.scanningView.SetDevices(m.devices)
	m.scanningView.SetSelectedIndex(m.scanSelectedIndex)
	m.scanningView.SetTableOffset(m.tableOffset)
	m.scanningView.SetShowingDetails(m.showingDetails)
	m.scanningView.SetScanningActive(m.scanningActive)
	m.scanningView.SetCurrentIP(m.currentIP)
	m.scanningView.SetProgress(m.scannedCount, m.totalIPs, m.discoveredCount)
	m.scanningView.SetScanStartTime(m.scanStartTime)
	m.scanningView.SetWorkerStats(m.workerStats)
	return m.scanningView.Render()
}

func main() {
	p := tea.NewProgram(
		initialModel(),
		tea.WithAltScreen(), // Use alternate screen buffer
	)

	if _, err := p.Run(); err != nil {
		fmt.Printf("Error running program: %v", err)
		os.Exit(1)
	}
}
