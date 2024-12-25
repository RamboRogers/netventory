package web

import (
	"embed"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/jackpal/gateway"
	"github.com/ramborogers/netventory/scanner"
	"github.com/ramborogers/netventory/views"
)

//go:embed all:templates/* all:static/css/* all:static/js/*
var content embed.FS

// Add color constants at the top of the file after imports
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorBold   = "\033[1m"
)

// Server represents the web interface server
type Server struct {
	port         int
	upgrader     websocket.Upgrader
	clients      map[*websocket.Conn]bool
	clientsMutex sync.RWMutex
	devices      map[string]scanner.Device
	deviceMutex  sync.RWMutex
	templates    *template.Template
	scanner      *scanner.Scanner
	scanActive   bool
	scanMutex    sync.RWMutex
	authToken    string
	staticFS     fs.FS
	version      string
	writeMutex   sync.Map // Per-connection write mutex
}

// NewServer creates a new web interface server
func NewServer(port int, authToken string, version string) (*Server, error) {
	// Parse templates from embedded filesystem
	templates, err := template.ParseFS(content, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %v", err)
	}

	// Create a sub-filesystem for static files
	staticFS, err := fs.Sub(content, "static")
	if err != nil {
		return nil, fmt.Errorf("failed to create static file system: %v", err)
	}

	// Verify critical files exist
	files := []string{
		"css/styles.css",
		"js/app.js",
	}
	for _, file := range files {
		if _, err := fs.Stat(staticFS, file); err != nil {
			return nil, fmt.Errorf("required static file missing - %s: %v", file, err)
		}
	}

	return &Server{
		port:      port,
		upgrader:  websocket.Upgrader{},
		clients:   make(map[*websocket.Conn]bool),
		devices:   make(map[string]scanner.Device),
		templates: templates,
		authToken: authToken,
		staticFS:  staticFS,
		version:   version,
	}, nil
}

// authenticateRequest checks if the request has a valid auth token
func (s *Server) authenticateRequest(r *http.Request) bool {
	token := r.URL.Query().Get("auth")
	return token == s.authToken
}

// Start initializes and starts the web server
func (s *Server) Start() error {

	// Authentication middleware
	authMiddleware := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token := r.URL.Query().Get("auth")
			clientIP := r.Header.Get("X-Real-IP")
			if clientIP == "" {
				clientIP = r.RemoteAddr
			}

			if !s.authenticateRequest(r) {
				log.Printf("%s[DENIED]%s Access attempt from %s - Invalid token: %s%s",
					colorRed, colorWhite, clientIP, token, colorReset)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			log.Printf("%s[AUTH]%s Successful access from %s%s",
				colorGreen, colorWhite, clientIP, colorReset)
			next(w, r)
		}
	}

	// Serve static files with auth
	fileServer := http.FileServer(http.FS(s.staticFS))
	http.HandleFunc("/static/", authMiddleware(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.TrimPrefix(r.URL.Path, "/static/")
		fileServer.ServeHTTP(w, r)
	}))

	// Handle main routes with auth
	http.HandleFunc("/", authMiddleware(s.handleIndex))
	http.HandleFunc("/ws", authMiddleware(s.handleWebSocket))
	http.HandleFunc("/save", authMiddleware(s.handleSaveScan))

	// Start server
	addr := fmt.Sprintf(":%d", s.port)
	//log.Printf("%s[SERVER]%s Web interface available at:%s", colorCyan, colorWhite, colorReset)
	//log.Printf("%s[URL]%s http://localhost%s?auth=%s%s",
	//	colorGreen, colorWhite, addr, s.authToken, colorReset)
	//	log.Printf("%s[URL]%s http://<your-ip>%s?auth=%s%s",
	//	colorGreen, colorWhite, addr, s.authToken, colorReset)
	return http.ListenAndServe(addr, nil)
}

// handleIndex serves the main page
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	// Get network interfaces
	interfaces, err := getNetworkInterfaces()
	if err != nil {
		log.Printf("Error getting network interfaces: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"Version":    s.version,
		"Interfaces": interfaces,
		"AuthToken":  s.authToken,
	}

	if err := s.templates.ExecuteTemplate(w, "index.html", data); err != nil {
		log.Printf("Error executing template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

// handleWebSocket handles WebSocket connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	clientIP := r.Header.Get("X-Real-IP")
	if clientIP == "" {
		clientIP = r.RemoteAddr
	}

	if !s.authenticateRequest(r) {
		log.Printf("%s[WS-DENIED]%s WebSocket connection attempt from %s - Invalid token%s",
			colorRed, colorWhite, clientIP, colorReset)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("%s[WS-ERROR]%s WebSocket upgrade failed from %s: %v%s",
			colorRed, colorWhite, clientIP, err, colorReset)
		return
	}
	defer conn.Close()

	log.Printf("%s[WS-CONNECT]%s New WebSocket connection from %s%s",
		colorGreen, colorWhite, clientIP, colorReset)

	// Register client
	s.clientsMutex.Lock()
	s.clients[conn] = true
	s.clientsMutex.Unlock()

	// Clean up when done
	defer func() {
		s.clientsMutex.Lock()
		delete(s.clients, conn)
		s.writeMutex.Delete(conn)
		s.clientsMutex.Unlock()
		log.Printf("%s[WS-DISCONNECT]%s Client disconnected: %s%s",
			colorYellow, colorWhite, clientIP, colorReset)
	}()

	// Send initial interface list
	interfaces, err := getNetworkInterfaces()
	if err == nil {
		conn.WriteJSON(map[string]interface{}{
			"type":       "interfaces",
			"interfaces": interfaces,
		})
	}

	// Send existing device data if available
	s.deviceMutex.RLock()
	if len(s.devices) > 0 {
		conn.WriteJSON(map[string]interface{}{
			"type":    "devices",
			"devices": s.devices,
			"total":   len(s.devices),
		})
	}
	s.deviceMutex.RUnlock()

	// Handle messages
	for {
		messageType, p, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		if messageType == websocket.TextMessage {
			var msg map[string]interface{}
			if err := json.Unmarshal(p, &msg); err != nil {
				log.Printf("Error parsing message: %v", err)
				continue
			}

			// Handle message types
			switch msg["type"] {
			case "start_scan":
				if range_, ok := msg["range"].(string); ok {
					log.Printf("Web client requested scan of %s", range_)
					if err := s.StartScan(range_); err != nil {
						conn.WriteJSON(map[string]interface{}{
							"type":  "error",
							"error": err.Error(),
						})
					}
				}
			case "stop_scan":
				s.StopScan()
			case "dump_scan":
				s.DumpScan()
				conn.WriteJSON(map[string]interface{}{
					"type": "scan_dumped",
				})
			}
		} else if messageType == websocket.PingMessage {
			if err := conn.WriteMessage(websocket.PongMessage, nil); err != nil {
				return
			}
		}
	}
}

// BroadcastUpdate sends an update to all connected WebSocket clients
func (s *Server) BroadcastUpdate(update interface{}) {
	s.clientsMutex.RLock()
	defer s.clientsMutex.RUnlock()

	for client := range s.clients {
		// Get or create mutex for this connection
		mutex, _ := s.writeMutex.LoadOrStore(client, &sync.Mutex{})
		writeMutex := mutex.(*sync.Mutex)

		// Protect the write with the mutex
		writeMutex.Lock()
		err := client.WriteJSON(update)
		writeMutex.Unlock()

		if err != nil {
			log.Printf("Failed to send update to client: %v", err)
			s.clientsMutex.RUnlock()
			s.clientsMutex.Lock()
			delete(s.clients, client)
			s.writeMutex.Delete(client)
			client.Close()
			s.clientsMutex.Unlock()
			s.clientsMutex.RLock()
		}
	}
}

// UpdateDevices updates the device list and broadcasts the change
func (s *Server) UpdateDevices(devices map[string]scanner.Device) {
	s.deviceMutex.Lock()
	s.devices = devices
	s.deviceMutex.Unlock()

	s.BroadcastUpdate(map[string]interface{}{
		"type":    "devices",
		"devices": devices,
	})
}

// UpdateProgress sends a progress update to all clients
func (s *Server) UpdateProgress(scanned, total, discovered int32) {
	s.BroadcastUpdate(map[string]interface{}{
		"type":       "progress",
		"scanned":    scanned,
		"total":      total,
		"discovered": discovered,
	})
}

// StartScan initiates a network scan
func (s *Server) StartScan(cidr string) error {
	s.scanMutex.Lock()
	if s.scanActive {
		s.scanMutex.Unlock()
		log.Printf("%s[SCAN-ERROR]%s Attempted to start scan while another is in progress%s",
			colorRed, colorWhite, colorReset)
		return fmt.Errorf("scan already in progress")
	}
	s.scanActive = true
	s.scanMutex.Unlock()

	log.Printf("%s[SCAN-START]%s Beginning network scan of %s%s",
		colorCyan, colorWhite, cidr, colorReset)

	// Create new scanner instance
	s.scanner = scanner.NewScanner(false) // debug disabled for web interface
	if s.scanner == nil {
		s.scanActive = false
		return fmt.Errorf("failed to create scanner")
	}

	// Reset device list
	s.deviceMutex.Lock()
	s.devices = make(map[string]scanner.Device)
	s.deviceMutex.Unlock()

	// Start scan in background
	go func() {
		defer func() {
			s.scanMutex.Lock()
			s.scanActive = false
			s.scanMutex.Unlock()
		}()

		if err := s.scanner.ScanNetwork(cidr, 50); err != nil {
			log.Printf("Scan error: %v", err)
			s.BroadcastUpdate(map[string]interface{}{
				"type":  "error",
				"error": err.Error(),
			})
			return
		}

		// Process results
		resultsChan, doneChan := s.scanner.GetResults()
		var discoveredCount int32

		// UpdateProgress sends a progress update to all clients
		progressDone := make(chan struct{})
		go func() {
			ticker := time.NewTicker(500 * time.Millisecond)
			defer ticker.Stop()
			defer close(progressDone)

			for {
				select {
				case <-doneChan:
					// Send one final progress update before exiting
					s.scanMutex.RLock()
					scanner := s.scanner
					s.scanMutex.RUnlock()

					if scanner != nil {
						stats := scanner.GetWorkerStats()
						if len(stats) > 0 {
							var totalIPs int32
							var scannedIPs int32
							for _, stat := range stats {
								totalIPs = stat.TotalIPs
								scannedIPs = stat.IPsScanned
								break
							}
							s.UpdateProgress(scannedIPs, totalIPs, atomic.LoadInt32(&discoveredCount))
						}
					}
					return
				case <-ticker.C:
					s.scanMutex.RLock()
					active := s.scanActive
					scanner := s.scanner
					s.scanMutex.RUnlock()

					if !active || scanner == nil {
						return
					}

					stats := scanner.GetWorkerStats()
					if len(stats) > 0 {
						var totalIPs int32
						var scannedIPs int32
						for _, stat := range stats {
							totalIPs = stat.TotalIPs
							scannedIPs = stat.IPsScanned
							break
						}
						s.UpdateProgress(scannedIPs, totalIPs, atomic.LoadInt32(&discoveredCount))
					}
				}
			}
		}()

		// Process results until done
		for {
			select {
			case device, ok := <-resultsChan:
				if !ok {
					// Channel closed, wait for doneChan
					continue
				}
				s.deviceMutex.Lock()
				s.devices[device.IPAddress] = device
				s.deviceMutex.Unlock()
				atomic.AddInt32(&discoveredCount, 1)
				s.UpdateDevices(s.devices)

			case <-doneChan:
				// Wait for progress goroutine to finish
				<-progressDone

				// Send final update
				s.deviceMutex.RLock()
				finalDevices := make(map[string]scanner.Device)
				for k, v := range s.devices {
					finalDevices[k] = v
				}
				s.deviceMutex.RUnlock()

				// Send final progress update
				s.scanMutex.RLock()
				scanner := s.scanner
				s.scanMutex.RUnlock()

				if scanner != nil {
					stats := scanner.GetWorkerStats()
					if len(stats) > 0 {
						var totalIPs int32
						var scannedIPs int32
						for _, stat := range stats {
							totalIPs = stat.TotalIPs
							scannedIPs = stat.IPsScanned
							break
						}
						s.UpdateProgress(scannedIPs, totalIPs, atomic.LoadInt32(&discoveredCount))
					}
				}

				// Send final device update
				s.BroadcastUpdate(map[string]interface{}{
					"type":    "devices",
					"devices": finalDevices,
					"total":   len(finalDevices),
				})

				// Send scan complete notification
				s.BroadcastUpdate(map[string]interface{}{
					"type":    "scan_complete",
					"message": "Scan Complete",
					"status":  "SCAN DONE",
				})

				// Ensure scan is marked as complete
				s.scanMutex.Lock()
				s.scanActive = false
				s.scanMutex.Unlock()
				return
			}
		}
	}()

	return nil
}

// StopScan stops the current scan
func (s *Server) StopScan() {
	s.scanMutex.Lock()
	defer s.scanMutex.Unlock()

	if s.scanActive && s.scanner != nil {
		log.Printf("%s[SCAN-STOP]%s Scan stopped by user request%s",
			colorYellow, colorWhite, colorReset)
		s.scanner.Stop()
		s.scanActive = false
	}
}

// DumpScan clears all scan data
func (s *Server) DumpScan() {
	log.Printf("%s[SCAN-DUMP]%s Clearing scan data%s",
		colorPurple, colorWhite, colorReset)

	// Stop any active scan first
	s.StopScan()

	// Clear device data
	s.deviceMutex.Lock()
	s.devices = make(map[string]scanner.Device)
	s.deviceMutex.Unlock()

	// Reset scan state
	s.scanMutex.Lock()
	s.scanActive = false
	s.scanner = nil // Clear scanner instance
	s.scanMutex.Unlock()

	// Broadcast empty device list to all clients
	s.BroadcastUpdate(map[string]interface{}{
		"type":    "devices",
		"devices": make(map[string]scanner.Device),
		"total":   0,
	})

	// Send scan complete notification
	s.BroadcastUpdate(map[string]interface{}{
		"type":    "scan_complete",
		"message": "Scan Data Cleared",
		"status":  "CLEARED",
	})
}

// CompareIPs compares two IP addresses for sorting
func CompareIPs(a, b string) int {
	aOctets := strings.Split(a, ".")
	bOctets := strings.Split(b, ".")

	for i := 0; i < 4; i++ {
		aNum, _ := strconv.Atoi(aOctets[i])
		bNum, _ := strconv.Atoi(bOctets[i])
		if aNum != bNum {
			return aNum - bNum
		}
	}
	return 0
}

// SaveScan generates a CSV export of the scan data
func (s *Server) SaveScan(w http.ResponseWriter) {
	s.deviceMutex.RLock()
	defer s.deviceMutex.RUnlock()

	log.Printf("%s[SCAN-SAVE]%s Exporting scan data to CSV%s",
		colorBlue, colorWhite, colorReset)

	// Set headers for CSV download
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=netventory-scan-"+time.Now().Format("2006-01-02-150405")+".csv")

	// Create CSV writer
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header with version and timestamp
	writer.Write([]string{"NetVentory " + s.version})
	writer.Write([]string{"https://github.com/RamboRogers/netventory"})
	writer.Write([]string{"Scan Date:", time.Now().Format("2006-01-02 15:04:05")})
	writer.Write([]string{}) // Empty line

	// Write CSV headers
	writer.Write([]string{
		"IP Address",
		"Hostname",
		"MAC Address",
		"Open Ports",
		"mDNS Name",
		"mDNS Services",
	})

	// Sort devices by IP for consistent output
	var ips []string
	for ip := range s.devices {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool {
		return CompareIPs(ips[i], ips[j]) < 0
	})

	// Write device data
	for _, ip := range ips {
		device := s.devices[ip]
		ports := make([]string, 0, len(device.OpenPorts))
		for _, port := range device.OpenPorts {
			ports = append(ports, fmt.Sprintf("%d", port))
		}

		// Format mDNS services
		var mdnsServices string
		if len(device.MDNSServices) > 0 {
			services := make([]string, 0, len(device.MDNSServices))
			for k, v := range device.MDNSServices {
				services = append(services, fmt.Sprintf("%s: %s", k, v))
			}
			mdnsServices = strings.Join(services, "; ")
		}

		writer.Write([]string{
			device.IPAddress,
			strings.Join(device.Hostname, ", "),
			device.MACAddress,
			strings.Join(ports, ", "),
			device.MDNSName,
			mdnsServices,
		})
	}
}

func (s *Server) handleSaveScan(w http.ResponseWriter, r *http.Request) {
	if !s.authenticateRequest(r) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	s.SaveScan(w)
}

// getNetworkInterfaces returns a list of network interfaces
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

func init() {
	// Initialize logger to write to stderr with timestamp
	log.SetFlags(log.Ldate | log.Ltime)
	// Ensure logger output isn't buffered
	log.SetOutput(os.Stderr)
}
