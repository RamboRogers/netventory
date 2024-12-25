package scanner

import (
	"bufio"
	"context"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"crypto/tls"
	"crypto/x509"

	"github.com/hashicorp/mdns"
	"github.com/hirochachacha/go-smb2"
)

var oidCommonName = asn1.ObjectIdentifier{2, 5, 4, 3}

// Device represents a discovered network device
type Device struct {
	IPAddress    string
	Hostname     []string          // Multiple hostnames possible
	MDNSName     string            // mDNS discovered name
	MDNSServices map[string]string // Map of service type to service info
	MACAddress   string
	Vendor       string
	DeviceType   string
	Interface    string
	Status       string // For showing discovery status
	OpenPorts    []int  // Separate ports from status
}

// Scanner handles network scanning operations
type Scanner struct {
	devices      map[string]Device
	deviceMutex  sync.RWMutex
	workerStats  map[int]*WorkerStatus
	statsLock    sync.RWMutex
	resultsChan  chan Device
	doneChan     chan bool
	reportFile   *os.File
	scannedCount int32                        // IPs completed (both online and offline)
	totalIPs     int32                        // Total number of IPs to scan
	sentCount    int32                        // Number of IPs sent to workers
	stopChan     chan struct{}                // Channel to signal stopping
	mdnsNames    map[string]string            // Map of IP to mDNS names
	mdnsServices map[string]map[string]string // Map of IP to service map
	mdnsMutex    sync.RWMutex
	mdnsWg       sync.WaitGroup // WaitGroup for tracking mDNS operations
}

// WorkerStatus tracks the status of each worker goroutine
type WorkerStatus struct {
	StartTime  time.Time
	LastSeen   time.Time
	CurrentIP  string
	State      string
	IPsFound   int32
	IPsScanned int32
	TotalIPs   int32
	SentCount  int32 // Track IPs sent to workers
}

// NewScanner creates a new scanner instance
func NewScanner(debug bool) *Scanner {
	s := &Scanner{
		devices:      make(map[string]Device),
		workerStats:  make(map[int]*WorkerStatus),
		resultsChan:  make(chan Device, 100),
		doneChan:     make(chan bool),
		scannedCount: 0,
		stopChan:     make(chan struct{}),
	}

	if debug {
		// Create/truncate report file only in debug mode
		f, err := os.OpenFile("report.log", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
		if err != nil {
			log.Printf("Error creating report file: %v", err)
			return nil
		}

		// Write header
		fmt.Fprintf(f, "=== Scan started at %s ===\n", time.Now().Format(time.RFC3339))
		fmt.Fprintf(f, "IP Address\tHostname\tmDNS Name\tMAC Address\tVendor\tStatus\tPorts\n")
		s.reportFile = f
	}

	return s
}

// Close closes the scanner and its report file
func (s *Scanner) Close() {
	if s.reportFile != nil {
		fmt.Fprintf(s.reportFile, "\n=== Scan completed at %s ===\n", time.Now().Format(time.RFC3339))
		s.reportFile.Close()
	}
}

// Stop signals the scanner to stop
func (s *Scanner) Stop() {
	close(s.stopChan)
}

// ScanNetwork starts scanning the specified CIDR range
func (s *Scanner) ScanNetwork(cidr string, workers int) error {
	// Reset stop channel
	s.stopChan = make(chan struct{})
	// Write scan parameters to report
	fmt.Fprintf(s.reportFile, "\nScanning network: %s with %d workers\n\n", cidr, workers)

	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return err
	}

	ips := GetAllIPs(ipNet)
	totalIPs := int32(len(ips))
	atomic.StoreInt32(&s.totalIPs, totalIPs)
	atomic.StoreInt32(&s.scannedCount, 0) // Reset counter
	atomic.StoreInt32(&s.sentCount, 0)    // Reset sent counter

	s.deviceMutex.Lock()
	s.devices = make(map[string]Device)
	s.deviceMutex.Unlock()

	workChan := make(chan net.IP, len(ips))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		workerID := i

		s.statsLock.Lock()
		s.workerStats[workerID] = &WorkerStatus{
			StartTime: time.Now(),
			State:     "starting",
			CurrentIP: "waiting",
			LastSeen:  time.Now(),
			TotalIPs:  totalIPs,
		}
		s.statsLock.Unlock()

		go s.worker(workerID, workChan, &wg)
	}

	// Feed IPs to workers
	go func() {
		for _, ip := range ips {
			select {
			case <-s.stopChan:
				close(workChan)
				return
			case workChan <- ip:
				atomic.AddInt32(&s.sentCount, 1)
			}
		}
		close(workChan)
	}()

	// Wait for completion in a goroutine
	go func() {
		log.Printf("Starting scan completion wait routine")

		// Wait for all workers to finish
		log.Printf("Waiting for %d workers to complete...", workers)
		wg.Wait()
		log.Printf("All workers have completed")

		remaining := atomic.LoadInt32(&s.sentCount) - atomic.LoadInt32(&s.scannedCount)
		if remaining > 0 {
			log.Printf("Found %d remaining IPs during completion", remaining)
			atomic.AddInt32(&s.scannedCount, remaining)
		}

		// Now wait for all mDNS operations to complete
		log.Printf("Workers complete, waiting for mDNS operations to finish...")
		s.mdnsWg.Wait()
		log.Printf("All mDNS operations complete")

		log.Printf("Scan completion routine finished, sending done signal")
		s.doneChan <- true
	}()

	return nil
}

func (s *Scanner) worker(id int, workChan chan net.IP, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() {
		s.statsLock.Lock()
		delete(s.workerStats, id)
		s.statsLock.Unlock()
	}()

	for ip := range workChan {
		select {
		case <-s.stopChan:
			return
		default:
			ipStr := ip.String()
			var mdnsWait sync.WaitGroup

			s.statsLock.Lock()
			if stat := s.workerStats[id]; stat != nil {
				stat.CurrentIP = ipStr
				stat.LastSeen = time.Now()
				stat.State = "scanning"
			}
			s.statsLock.Unlock()

			if reachable, openPorts := IsReachable(ipStr); reachable {
				device := Device{
					IPAddress: ipStr,
					Status:    "Up",
					OpenPorts: openPorts,
				}

				// Try to get MAC address - retry a few times if needed
				for i := 0; i < 3; i++ {
					if mac := GetMACFromIP(ipStr); mac != "" {
						device.MACAddress = mac
						device.Vendor = LookupVendor(mac)
						// Check if it's a Mac based on vendor
						if strings.Contains(strings.ToLower(device.Vendor), "apple") {
							log.Printf("DEBUG: Detected Apple device at %s based on MAC vendor", ipStr)
							device.DeviceType = "Apple"
						}
						break
					}
					time.Sleep(time.Millisecond * 100) // Brief pause between retries
				}

				// Add any mDNS info from our pre-sweep
				if mdnsName, mdnsServices := s.getMDNSInfo(ipStr); mdnsName != "" {
					device.MDNSName = mdnsName
					device.MDNSServices = mdnsServices
					log.Printf("DEBUG: Using pre-collected mDNS for %s - Name: %s, Services: %v",
						ipStr, mdnsName, mdnsServices)

					// Check for Apple-specific mDNS services
					for service := range mdnsServices {
						if strings.Contains(service, "apple") ||
							strings.Contains(service, "airport") ||
							strings.Contains(service, "airplay") ||
							strings.Contains(service, "homekit") {
							log.Printf("DEBUG: Detected Apple device at %s based on mDNS service: %s", ipStr, service)
							device.DeviceType = "Apple"
							break
						}
					}
				}

				// Try DNS lookup first
				if names, err := net.LookupAddr(ipStr); err == nil && len(names) > 0 {
					device.Hostname = names
					log.Printf("DNS hostname found for %s: %v", ipStr, names)
				} else {
					// Try protocol-specific resolution methods
					if contains(openPorts, 548) {
						log.Printf("DNS lookup failed for %s, trying AFP resolution", ipStr)
						if afpHostname, err := getAFPHostname(ipStr); err == nil && afpHostname != "" {
							device.Hostname = []string{afpHostname}
							device.DeviceType = "Apple" // AFP is specific to Apple
							log.Printf("Got AFP hostname for %s: %s", ipStr, afpHostname)
						} else {
							log.Printf("AFP hostname resolution failed for %s: %v", ipStr, err)
						}
					}

					// Try other protocols if still no hostname
					if len(device.Hostname) == 0 {
						if len(device.Hostname) == 0 && contains(openPorts, 445) {
							log.Printf("Trying NetBIOS/SMB resolution for %s", ipStr)
							if nbName, err := getNetBIOSName(ipStr); err == nil && nbName != "" {
								device.Hostname = []string{nbName}
								log.Printf("Got NetBIOS name for %s: %s", ipStr, nbName)
							} else if smbHostname, err := getSMBHostname(ipStr); err == nil && smbHostname != "" {
								device.Hostname = []string{smbHostname}
								log.Printf("Got SMB hostname for %s: %s", ipStr, smbHostname)
							}
						}

						if len(device.Hostname) == 0 && contains(openPorts, 3389) {
							log.Printf("Trying RDP resolution for %s", ipStr)
							if rdpHostname, err := getRDPHostname(ipStr); err == nil && rdpHostname != "" {
								device.Hostname = []string{rdpHostname}
								log.Printf("Got RDP hostname for %s: %s", ipStr, rdpHostname)
							}
						}

						// Only try mDNS if we still don't have a hostname and it's likely an Apple device
						if len(device.Hostname) == 0 && (device.DeviceType == "Apple" || device.DeviceType == "Possible Apple" ||
							contains(openPorts, 5353) || // mDNS port
							contains(openPorts, 5000) || // AirPlay
							contains(openPorts, 7000)) { // AirPlay alternate
							log.Printf("No hostname found via other methods, initiating mDNS resolution for %s (worker %d)", ipStr, id)
							mdnsWait.Add(1)
							go func() {
								defer func() {
									mdnsWait.Done()
									log.Printf("Local mDNS wait completed for %s (worker %d)", ipStr, id)
								}()

								if bonjourHostname, err := getBonjourHostname(s, ipStr); err == nil && bonjourHostname != "" {
									s.deviceMutex.Lock()
									device.Hostname = []string{bonjourHostname}
									// Check if it's an Apple device based on the service type
									if device.DeviceType == "" {
										device.DeviceType = "Possible Apple"
									}
									s.deviceMutex.Unlock()
									log.Printf("Successfully resolved mDNS hostname for %s: %s (worker %d)", ipStr, bonjourHostname, id)
								} else {
									log.Printf("mDNS resolution failed for %s: %v (worker %d)", ipStr, err, id)
								}
							}()
						} else if len(device.Hostname) > 0 {
							log.Printf("Skipping mDNS resolution for %s - hostname already found via other methods", ipStr)
						}
					}
				}

				// Check for Mac-specific ports as additional identifier
				if contains(openPorts, 548) || // AFP
					contains(openPorts, 5353) || // mDNS
					contains(openPorts, 5000) || // AirPlay
					contains(openPorts, 7000) || // AirPlay alternate
					contains(openPorts, 3689) { // iTunes sharing
					if device.DeviceType == "" {
						device.DeviceType = "Possible Apple"
						log.Printf("DEBUG: Marked %s as possible Apple device based on open ports", ipStr)
					}
				}

				// Wait for mDNS resolution to complete before proceeding
				log.Printf("Waiting for mDNS operations to complete for %s (worker %d)", ipStr, id)
				mdnsWait.Wait()
				log.Printf("All mDNS operations completed for %s (worker %d)", ipStr, id)

				s.statsLock.Lock()
				if stat := s.workerStats[id]; stat != nil {
					atomic.AddInt32(&stat.IPsFound, 1)
				}
				s.statsLock.Unlock()

				// Store device in map
				s.deviceMutex.Lock()
				s.devices[ipStr] = device
				s.deviceMutex.Unlock()

				// Write to report file
				hostnames := "N/A"
				if len(device.Hostname) > 0 {
					hostnames = strings.Join(device.Hostname, ",")
				}

				// Format mDNS services for logging
				var mdnsInfo string
				if device.MDNSName != "" {
					mdnsInfo = device.MDNSName
					if len(device.MDNSServices) > 0 {
						var services []string
						for svcType, svcInfo := range device.MDNSServices {
							services = append(services, fmt.Sprintf("%s: %s", svcType, svcInfo))
						}
						mdnsInfo += fmt.Sprintf(" (Services: %s)", strings.Join(services, ", "))
					}
				} else {
					mdnsInfo = "No mDNS"
				}

				log.Printf("Found device: %s (MAC: %s, Vendor: %s, mDNS: %s, Ports: %v)",
					ipStr, device.MACAddress, device.Vendor, mdnsInfo, device.OpenPorts)
				fmt.Fprintf(s.reportFile, "%s\t%s\t%s\t%s\t%s\t%s\t%v\n",
					device.IPAddress,
					hostnames,
					device.MDNSName,
					device.MACAddress,
					device.Vendor,
					device.Status,
					device.OpenPorts)

				select {
				case s.resultsChan <- device:
					log.Printf("Sent device %s to results channel", ipStr)
				default:
					log.Printf("Warning: Results channel full, skipping device %s", ipStr)
				}
			} else {
				// Store offline device
				device := Device{
					IPAddress: ipStr,
					Status:    "Down",
				}
				s.deviceMutex.Lock()
				s.devices[ipStr] = device
				s.deviceMutex.Unlock()
			}

			// Only increment the scan counter after all operations (including mDNS) are complete
			atomic.AddInt32(&s.scannedCount, 1)
			log.Printf("Completed all operations for %s (worker %d, scanned: %d/%d)",
				ipStr, id, atomic.LoadInt32(&s.scannedCount), atomic.LoadInt32(&s.totalIPs))

			// Update worker stats with completed count
			s.statsLock.Lock()
			if stat := s.workerStats[id]; stat != nil {
				atomic.StoreInt32(&stat.IPsScanned, atomic.LoadInt32(&s.scannedCount))
				atomic.StoreInt32(&stat.TotalIPs, atomic.LoadInt32(&s.totalIPs))
				atomic.StoreInt32(&stat.SentCount, atomic.LoadInt32(&s.sentCount))
			}
			s.statsLock.Unlock()
		}
	}
}

// GetResults returns the channels for receiving scan results
func (s *Scanner) GetResults() (chan Device, chan bool) {
	return s.resultsChan, s.doneChan
}

// GetWorkerStats returns a copy of current worker statistics
func (s *Scanner) GetWorkerStats() map[int]WorkerStatus {
	s.statsLock.RLock()
	defer s.statsLock.RUnlock()

	stats := make(map[int]WorkerStatus, len(s.workerStats))
	scanned := atomic.LoadInt32(&s.scannedCount)
	sent := atomic.LoadInt32(&s.sentCount)
	total := atomic.LoadInt32(&s.totalIPs)

	// If we have no workers but have devices, we're done - return final stats
	if len(s.workerStats) == 0 {
		if len(s.devices) > 0 {
			stats[0] = WorkerStatus{
				StartTime:  time.Now(),
				LastSeen:   time.Now(),
				State:      "completed",
				IPsFound:   int32(len(s.devices)),
				IPsScanned: total, // Use total IPs as scanned count
				TotalIPs:   total,
				SentCount:  total, // All IPs were sent
			}
		}
		return stats
	}

	// Create stats with the current global counts
	for id, stat := range s.workerStats {
		copyStat := *stat
		copyStat.IPsScanned = scanned
		copyStat.TotalIPs = total
		copyStat.SentCount = sent
		stats[id] = copyStat
	}

	return stats
}

// IsReachable checks if a host is reachable using various methods
func IsReachable(ip string) (bool, []int) {
	log.Printf("Checking reachability for %s", ip)
	var openPorts []int
	isReachable := false

	// First check ARP cache and actively probe - fastest method for local devices
	if mac := GetMACFromIP(ip); mac != "" {
		log.Printf("%s found in ARP cache/probe with MAC %s", ip, mac)
		isReachable = true
		// Continue checking ports even if found via ARP
	}

	// Try common TCP ports with moderate timeout
	commonPorts := []int{80, 443, 22, 445, 139, 135, 8080, 3389, 5900, 8006}

	// Create a channel for collecting results
	results := make(chan int, len(commonPorts))
	var wg sync.WaitGroup

	// Check ports concurrently
	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			log.Printf("Trying TCP port %d for %s", p, ip)
			d := net.Dialer{Timeout: time.Millisecond * 750}
			conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", ip, p))
			if err == nil {
				conn.Close()
				log.Printf("%s is reachable via TCP port %d", ip, p)
				results <- p
				isReachable = true
			}
		}(port)
	}

	// Check Mac-specific ports separately with longer timeouts
	macPorts := []struct {
		port    int
		timeout time.Duration
	}{
		{548, time.Second * 3},  // AFP needs more time
		{5353, time.Second * 2}, // mDNS
		{5000, time.Second * 1}, // AirPlay
		{7000, time.Second * 1}, // AirPlay alternate
		{3689, time.Second * 1}, // iTunes sharing
	}

	for _, macPort := range macPorts {
		wg.Add(1)
		go func(p int, timeout time.Duration) {
			defer wg.Done()
			log.Printf("Trying Mac-specific port %d for %s with %v timeout", p, ip, timeout)

			if p == 5353 {
				// Special handling for mDNS (UDP)
				conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:%d", ip, p), timeout)
				if err == nil {
					// Send a minimal mDNS query
					query := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
					conn.Write(query)
					conn.SetReadDeadline(time.Now().Add(timeout))
					buffer := make([]byte, 32)
					_, err := conn.Read(buffer)
					conn.Close()
					if err == nil {
						log.Printf("%s responded to mDNS query on port %d", ip, p)
						results <- p
						isReachable = true
					}
				}
			} else {
				// TCP ports
				d := net.Dialer{Timeout: timeout}
				conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", ip, p))
				if err == nil {
					conn.Close()
					log.Printf("%s is reachable via Mac-specific TCP port %d", ip, p)
					results <- p
					isReachable = true
				}
			}
		}(macPort.port, macPort.timeout)
	}

	// Wait for all port checks to complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	for port := range results {
		openPorts = append(openPorts, port)
	}

	// Sort ports for consistent output
	sort.Ints(openPorts)
	return isReachable, openPorts
}

// GetAllIPs returns all IP addresses in a subnet
func GetAllIPs(ipNet *net.IPNet) []net.IP {
	var ips []net.IP
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		newIP := make(net.IP, len(ip))
		copy(newIP, ip)
		ips = append(ips, newIP)
	}
	if len(ips) > 2 {
		ips = ips[1 : len(ips)-1]
	}
	return ips
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// getMDNSInfo safely retrieves mDNS info from the maps
func (s *Scanner) getMDNSInfo(ip string) (string, map[string]string) {
	s.mdnsMutex.RLock()
	defer s.mdnsMutex.RUnlock()

	log.Printf("DEBUG: getMDNSInfo for %s - Names: %v, Services: %v",
		ip, s.mdnsNames[ip], s.mdnsServices[ip])

	services := make(map[string]string)
	if s.mdnsServices[ip] != nil {
		for k, v := range s.mdnsServices[ip] {
			services[k] = v
		}
	}
	return s.mdnsNames[ip], services
}

// Add new function for SMB hostname resolution
func getSMBHostname(ip string) (string, error) {
	log.Printf("Attempting SMB hostname resolution for %s", ip)

	// Set up SMB connection with guest credentials
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", ip), time.Second*2)
	if err != nil {
		log.Printf("SMB connection failed for %s: %v", ip, err)
		return "", fmt.Errorf("SMB connection failed: %v", err)
	}
	defer conn.Close()
	log.Printf("SMB connection established to %s", ip)

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     "Guest",
			Password: "",
		},
	}

	log.Printf("Attempting SMB session with Guest account for %s", ip)
	s, err := d.Dial(conn)
	if err != nil {
		log.Printf("SMB session failed for %s with Guest account: %v", ip, err)
		// Try with empty credentials as fallback
		log.Printf("Retrying SMB session with empty credentials for %s", ip)
		d.Initiator = &smb2.NTLMInitiator{
			User:     "",
			Password: "",
		}
		s, err = d.Dial(conn)
		if err != nil {
			log.Printf("SMB session failed for %s with empty credentials: %v", ip, err)
			return "", fmt.Errorf("SMB session failed: %v", err)
		}
	}
	defer s.Logoff()
	log.Printf("SMB session established with %s", ip)

	// Try to get hostname from shares list
	shares, err := s.ListSharenames()
	if err != nil {
		log.Printf("Failed to list shares for %s: %v", ip, err)
		return "", fmt.Errorf("failed to list shares: %v", err)
	}
	log.Printf("Retrieved shares from %s: %v", ip, shares)

	// The IPC$ share often contains the hostname
	for _, share := range shares {
		log.Printf("Analyzing share: %s", share)
		if strings.HasPrefix(share, "\\\\") {
			// Extract hostname from UNC path
			parts := strings.Split(share[2:], "\\")
			if len(parts) > 0 {
				serverName := strings.TrimSpace(parts[0])
				serverName = strings.Split(serverName, ".")[0] // Take first part of FQDN
				log.Printf("Found SMB hostname for %s: %s (from share: %s)", ip, serverName, share)
				return serverName, nil
			}
		}
	}

	log.Printf("No SMB hostname found for %s in shares: %v", ip, shares)
	return "", fmt.Errorf("no hostname found")
}

// Helper function to check if a slice contains a value
func contains(slice []int, val int) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

// Add NetBIOS name resolution function
func getNetBIOSName(ip string) (string, error) {
	log.Printf("Attempting NetBIOS name resolution for %s", ip)

	// NetBIOS name query packet
	// This is a status query which will return all names registered by the host
	query := []byte{
		0x80, 0x94, // Transaction ID
		0x00, 0x00, // Flags
		0x00, 0x01, // Questions
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		// Query name CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (encoded "*)
		0x20,       // Length byte
		0x43, 0x4b, // First two chars: CK
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x00,       // End of name
		0x00, 0x21, // Type: NetBIOS Status
		0x00, 0x01, // Class: IN
	}

	// Create UDP connection with timeout
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:137", ip), time.Second*1)
	if err != nil {
		log.Printf("NetBIOS connection failed for %s: %v", ip, err)
		return "", fmt.Errorf("NetBIOS connection failed: %v", err)
	}
	defer conn.Close()

	// Send query
	if _, err := conn.Write(query); err != nil {
		log.Printf("Failed to send NetBIOS query to %s: %v", ip, err)
		return "", err
	}
	log.Printf("Sent NetBIOS status query to %s", ip)

	// Read response with shorter timeout
	response := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Millisecond * 500))
	n, err := conn.Read(response)
	if err != nil {
		log.Printf("Failed to read NetBIOS response from %s: %v", ip, err)
		return "", err
	}
	log.Printf("Received %d bytes from %s: %x", n, ip, response[:min(n, 64)])

	// Parse response
	if n < 57 {
		log.Printf("NetBIOS response too short from %s: %d bytes", ip, n)
		return "", fmt.Errorf("response too short")
	}

	// Extract the number of names from the response
	numNames := int(response[56])
	log.Printf("Found %d NetBIOS names for %s", numNames, ip)

	if n < 57+numNames*18 {
		log.Printf("Incomplete NetBIOS response from %s", ip)
		return "", fmt.Errorf("incomplete response")
	}

	// Look through all names in the response
	for i := 0; i < numNames; i++ {
		offset := 57 + (i * 18)
		nameBytes := response[offset : offset+15]
		nameType := response[offset+15]
		flags := binary.BigEndian.Uint16(response[offset+16 : offset+18])

		// Convert name bytes to string (trim spaces and null bytes)
		name := strings.TrimRight(string(nameBytes), " \x00")
		log.Printf("Name[%d]: '%s' (type=0x%02x, flags=0x%04x)", i, name, nameType, flags)

		// First pass: look for machine names (flags 0x0400)
		if (nameType == 0x00 || nameType == 0x20) && (flags == 0x0400) {
			cleaned := cleanHostname(name)
			if cleaned != "" {
				log.Printf("Found NetBIOS machine name for %s: %s (type=0x%02x, flags=0x%04x)",
					ip, cleaned, nameType, flags)
				return cleaned, nil
			}
		}
	}

	// Second pass: if no machine name found, look for any registered name
	for i := 0; i < numNames; i++ {
		offset := 57 + (i * 18)
		nameBytes := response[offset : offset+15]
		nameType := response[offset+15]
		flags := binary.BigEndian.Uint16(response[offset+16 : offset+18])

		// Skip group names
		if flags&0x8000 != 0 {
			continue
		}

		// Convert name bytes to string (trim spaces and null bytes)
		name := strings.TrimRight(string(nameBytes), " \x00")

		// Check for workstation/server service
		if nameType == 0x00 || nameType == 0x20 {
			cleaned := cleanHostname(name)
			if cleaned != "" {
				log.Printf("Found NetBIOS alternate name for %s: %s (type=0x%02x, flags=0x%04x)",
					ip, cleaned, nameType, flags)
				return cleaned, nil
			}
		}
	}

	log.Printf("No suitable NetBIOS name found for %s", ip)
	return "", fmt.Errorf("no NetBIOS name found")
}

// Add RDP hostname resolution function
func getRDPHostname(ip string) (string, error) {
	log.Printf("Attempting RDP hostname resolution for %s", ip)

	// Step 1: Initial X.224 Connection Request
	packet := []byte{
		// TPKT Header
		0x03, 0x00,
		0x00, 0x13, // Length: 19 bytes
		// COTP Header
		0x0e,       // Length: 14 bytes
		0xe0,       // Connection Request
		0x00, 0x00, // Dst Reference
		0x00, 0x00, // Src Reference
		0x00, // Class 0
		// RDP Negotiation Request
		0x01,       // Type: RDP Negotiation Request
		0x00,       // Flags
		0x08, 0x00, // Length
		0x07, 0x00, 0x00, 0x00, // Protocols: Standard RDP (1) + TLS (2) + CredSSP (4)
	}

	// Step 2: Establish TCP connection
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:3389", ip), time.Second*2)
	if err != nil {
		log.Printf("TCP connection to RDP server %s failed: %v", ip, err)
		return "", fmt.Errorf("TCP connection failed: %v", err)
	}
	defer conn.Close()
	log.Printf("TCP connection established to RDP server %s", ip)

	// Step 3: Send RDP Negotiation Request
	if _, err := conn.Write(packet); err != nil {
		log.Printf("Failed to send RDP negotiation request to %s: %v", ip, err)
		return "", fmt.Errorf("failed to send negotiation request: %v", err)
	}
	log.Printf("Sent RDP negotiation request to %s (requesting protocols: RDP + TLS + CredSSP)", ip)

	// Step 4: Read Response
	response := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Second * 2))
	n, err := conn.Read(response)
	if err != nil {
		log.Printf("Failed to read RDP response from %s: %v", ip, err)
		return "", fmt.Errorf("failed to read response: %v", err)
	}
	log.Printf("Received %d bytes from %s: %x", n, ip, response[:min(n, 64)])

	// Step 5: Parse Response
	if n < 19 {
		log.Printf("Response too short from %s (got %d bytes, need at least 19)", ip, n)
		return "", fmt.Errorf("response too short")
	}

	// Check TPKT header (0x03, 0x00)
	if response[0] != 0x03 || response[1] != 0x00 {
		log.Printf("Invalid TPKT header from %s: %x %x", ip, response[0], response[1])
		return "", fmt.Errorf("invalid TPKT header")
	}

	// Check COTP header
	if response[5] != 0xd0 {
		log.Printf("Invalid COTP header from %s: %x", ip, response[5])
		return "", fmt.Errorf("invalid COTP header")
	}

	// Parse selected protocol
	selectedProtocol := binary.LittleEndian.Uint32(response[15:19])
	log.Printf("RDP server %s protocol support:", ip)
	log.Printf("  Standard RDP: %v", selectedProtocol&0x01 != 0)
	log.Printf("  TLS: %v", selectedProtocol&0x02 != 0)
	log.Printf("  CredSSP: %v", selectedProtocol&0x04 != 0)
	log.Printf("  Early Auth: %v", selectedProtocol&0x08 != 0)
	log.Printf("  Server Cert: %v", selectedProtocol&0x10 != 0)

	// If server supports TLS or CredSSP, try SSL handshake
	if selectedProtocol&0x06 != 0 { // Check for TLS (0x02) or CredSSP (0x04)
		log.Printf("RDP server %s supports secure protocols (0x%x), initiating SSL handshake", ip, selectedProtocol)

		// Create new connection for SSL handshake
		sslConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:3389", ip), time.Second*2)
		if err != nil {
			return "", fmt.Errorf("SSL connection failed: %v", err)
		}
		defer sslConn.Close()

		// Send same negotiation request
		if _, err := sslConn.Write(packet); err != nil {
			return "", fmt.Errorf("SSL negotiation failed: %v", err)
		}

		// Read response
		if _, err := sslConn.Read(response[:19]); err != nil {
			return "", fmt.Errorf("SSL response failed: %v", err)
		}

		// Proceed with SSL handshake
		return getRDPHostnameSSL(sslConn, ip)
	}

	log.Printf("RDP server %s only supports basic RDP (protocol=0x%x)", ip, selectedProtocol)
	return "", fmt.Errorf("secure protocols not supported")
}

// Helper function for SSL/TLS based hostname resolution
func getRDPHostnameSSL(conn net.Conn, ip string) (string, error) {
	// Create TLS connection with custom config
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS13,
		// Accept any certificate
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			log.Printf("Received %d raw certificates from %s", len(rawCerts), ip)
			for i, cert := range rawCerts {
				log.Printf("Certificate %d size: %d bytes", i+1, len(cert))
			}
			return nil
		},
	})

	// Perform TLS Handshake with context and timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		log.Printf("TLS handshake with %s failed: %v", ip, err)
		// Even if handshake fails, try to get the certificate
		state := tlsConn.ConnectionState()
		log.Printf("Connection state for %s: Version=0x%x, HandshakeComplete=%v, CipherSuite=0x%x",
			ip, state.Version, state.HandshakeComplete, state.CipherSuite)
		if len(state.PeerCertificates) > 0 {
			log.Printf("Got certificate despite handshake failure for %s", ip)
			cert := state.PeerCertificates[0]
			return extractHostnameFromCert(cert, ip)
		}
		return "", fmt.Errorf("TLS handshake failed: %v", err)
	}

	// Extract Certificate Information
	state := tlsConn.ConnectionState()
	log.Printf("Final connection state for %s: Version=0x%x, HandshakeComplete=%v, CipherSuite=0x%x",
		ip, state.Version, state.HandshakeComplete, state.CipherSuite)

	if len(state.PeerCertificates) > 0 {
		log.Printf("Successfully retrieved %d certificates from %s", len(state.PeerCertificates), ip)
		return extractHostnameFromCert(state.PeerCertificates[0], ip)
	}

	log.Printf("No certificates received from %s", ip)
	return "", fmt.Errorf("no certificates available")
}

// Helper function to extract hostname from certificate
func extractHostnameFromCert(cert *x509.Certificate, ip string) (string, error) {
	log.Printf("Analyzing certificate from %s:", ip)
	log.Printf("  Subject: %v", cert.Subject)
	log.Printf("  Issuer: %v", cert.Issuer)
	log.Printf("  DNS Names: %v", cert.DNSNames)
	log.Printf("  IP Addresses: %v", cert.IPAddresses)
	log.Printf("  Common Name: %s", cert.Subject.CommonName)
	log.Printf("  Organization: %v", cert.Subject.Organization)

	// Try all possible hostname sources
	possibleNames := make([]string, 0)

	// 1. DNS Names
	possibleNames = append(possibleNames, cert.DNSNames...)
	log.Printf("Added %d DNS names to possible names", len(cert.DNSNames))

	// 2. Common Name
	if cert.Subject.CommonName != "" {
		possibleNames = append(possibleNames, cert.Subject.CommonName)
		log.Printf("Added Common Name to possible names: %s", cert.Subject.CommonName)
	}

	// 3. Organization Name (some self-signed certs put hostname here)
	if len(cert.Subject.Organization) > 0 {
		possibleNames = append(possibleNames, cert.Subject.Organization...)
		log.Printf("Added %d Organization names to possible names", len(cert.Subject.Organization))
	}

	// 4. Subject Alternative Names
	for _, name := range cert.Subject.Names {
		if name.Type.Equal(oidCommonName) {
			if value, ok := name.Value.(string); ok && value != "" {
				possibleNames = append(possibleNames, value)
				log.Printf("Added SAN to possible names: %s", value)
			}
		}
	}

	log.Printf("Total possible names found for %s: %d", ip, len(possibleNames))
	// Try each name
	for _, name := range possibleNames {
		if name != "" && !strings.Contains(name, "*") {
			log.Printf("Processing possible name for %s: %s", ip, name)
			cleaned := cleanHostname(name)
			log.Printf("Cleaned hostname: %s", cleaned)
			if cleaned != "" && isValidHostname(cleaned) {
				log.Printf("Found valid hostname in certificate for %s: %s (from %s)",
					ip, cleaned, name)
				return cleaned, nil
			} else {
				log.Printf("Invalid hostname after cleaning: %s", cleaned)
			}
		}
	}

	log.Printf("No valid hostname found in certificate fields for %s", ip)
	return "", fmt.Errorf("no valid hostname in certificate")
}

// Helper function to clean hostnames from certificates
func cleanHostname(name string) string {
	// Remove any port numbers
	if idx := strings.Index(name, ":"); idx != -1 {
		name = name[:idx]
	}

	// Take first part of FQDN
	name = strings.Split(name, ".")[0]

	// Remove any spaces or special characters
	name = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') ||
			(r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') ||
			r == '-' {
			return r
		}
		return -1
	}, name)

	return name
}

func isValidHostname(s string) bool {
	if len(s) < 2 || len(s) > 63 {
		return false
	}
	// Must start with letter
	if !((s[0] >= 'a' && s[0] <= 'z') || (s[0] >= 'A' && s[0] <= 'Z')) {
		return false
	}
	// Must end with letter or digit
	last := s[len(s)-1]
	if !((last >= 'a' && last <= 'z') || (last >= 'A' && last <= 'Z') || (last >= '0' && last <= '9')) {
		return false
	}
	// Check for invalid characters
	return !strings.ContainsAny(s, "\\/:*?\"<>|@")
}

// Helper function for min
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Add new function for AFP hostname resolution
func getAFPHostname(ip string) (string, error) {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:548", ip), time.Second*2)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	// Read initial banner
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}

	log.Printf("DEBUG: AFP banner from %s: %s", ip, banner)

	// Look for hostname in AFP banner
	// Common format: "AFP/TCP AFPServer (name)"
	if strings.Contains(banner, "AFP") {
		parts := strings.Split(banner, "(")
		if len(parts) > 1 {
			hostname := strings.TrimRight(parts[1], ")\r\n")
			if hostname != "" {
				log.Printf("DEBUG: Found AFP hostname for %s: %s", ip, hostname)
				return hostname, nil
			}
		}
	}

	return "", fmt.Errorf("no hostname in AFP banner")
}

// Add new function for Bonjour hostname resolution
func getBonjourHostname(s *Scanner, ip string) (string, error) {
	log.Printf("Starting mDNS resolution for %s (adding to WaitGroup)", ip)

	// Add to WaitGroup before starting mDNS operations
	s.mdnsWg.Add(1)
	defer func() {
		s.mdnsWg.Done()
		log.Printf("Completed mDNS resolution for %s (removed from WaitGroup)", ip)
	}()

	// Common Apple and network service types - reduced list to most common ones
	serviceTypes := []string{
		"_device-info._tcp",
		"_airplay._tcp",
		"_raop._tcp",
		"_companion-link._tcp",
		"_apple-mobdev._tcp",
		"_apple-mobdev2._tcp",
		"_apple-pairable._tcp",
		"_homekit._tcp",
		"_touch-able._tcp",
		"_http._tcp",
	}

	// Try each service type with shorter timeout
	for _, service := range serviceTypes {
		log.Printf("Querying for service type: %s", service)

		// Create a channel to receive entries
		entryChan := make(chan *mdns.ServiceEntry, 10)
		go func(ch chan *mdns.ServiceEntry) {
			defer close(ch)
			// Create query parameters with shorter timeout
			params := &mdns.QueryParam{
				Service:             service,
				Domain:              "local",
				Timeout:             time.Millisecond * 250, // Reduced from 1 second
				Entries:             ch,
				DisableIPv6:         true,
				WantUnicastResponse: true,
			}

			if err := mdns.Query(params); err != nil {
				log.Printf("Failed to query service %s: %v", service, err)
				return
			}
		}(entryChan)

		// Process results with shorter timeout
		timeout := time.After(time.Millisecond * 300) // Reduced from 1 second
	L:
		for {
			select {
			case entry, ok := <-entryChan:
				if !ok {
					break L
				}
				if entry.AddrV4.String() == ip {
					log.Printf("Found matching mDNS entry for %s: %+v", ip, entry)

					// Try host first (usually cleaner)
					if entry.Host != "" {
						hostname := strings.TrimSuffix(entry.Host, ".")
						if hostname != "" {
							log.Printf("Using host name for %s: %s", ip, hostname)
							return hostname, nil
						}
					}

					// Try service name next
					if entry.Name != "" {
						name := entry.Name
						if idx := strings.Index(name, "@"); idx > 0 {
							name = name[idx+1:]
						}
						if idx := strings.Index(name, "._"); idx > 0 {
							name = name[:idx]
						}
						if !strings.HasSuffix(name, ".local") {
							name += ".local"
						}
						log.Printf("Using service name for %s: %s", ip, name)
						return name, nil
					}
				}
			case <-timeout:
				log.Printf("Timeout querying service %s for %s", service, ip)
				break L
			}
		}
	}

	return "", fmt.Errorf("no hostname found via mDNS")
}
