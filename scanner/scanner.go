package scanner

import (
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hashicorp/mdns"
)

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

// sweepMDNS performs a network-wide mDNS discovery
func (s *Scanner) sweepMDNS() {
	s.mdnsNames = make(map[string]string)
	s.mdnsServices = make(map[string]map[string]string)

	// Direct service types to browse
	services := []string{
		"_workstation._tcp", // Basic workstation presence
		"_http._tcp",        // HTTP servers
		"_https._tcp",       // HTTPS servers
		"_ssh._tcp",         // SSH servers
		"_sftp-ssh._tcp",    // SFTP servers
		"_smb._tcp",         // SMB/CIFS servers
	}

	log.Printf("Starting mDNS browse for services: %v", services)

	// Browse each service type
	for _, service := range services {
		// Browse for instances of this service
		entriesCh := make(chan *mdns.ServiceEntry, 100)
		done := make(chan bool)
		browseDone := make(chan bool)

		// Start collecting results for this service
		go func(svcType string) {
			for entry := range entriesCh {
				if entry != nil {
					// Extract just the instance name (e.g., "QNAP2" from "QNAP2 [00:02:c9:23:c5:a0]._workstation._tcp")
					name := entry.Name
					if idx := strings.Index(name, "._"); idx > 0 {
						name = name[:idx]
					}
					// Clean up the name - remove any MAC address or other metadata in brackets
					if idx := strings.Index(name, " ["); idx > 0 {
						name = name[:idx]
					}
					name = strings.TrimSuffix(name, ".local")
					name = strings.ReplaceAll(name, "\\", "") // Remove escapes
					log.Printf("DEBUG: Found %s service: %s", svcType, name)

					// First do a direct query for the host
					hostEntriesCh := make(chan *mdns.ServiceEntry, 10)
					hostDone := make(chan bool)
					var directQueryIP string
					var confirmedHost string

					// Start collecting host query results
					go func() {
						for entry := range hostEntriesCh {
							if entry != nil && entry.AddrV4 != nil {
								ip := entry.AddrV4.String()
								host := strings.TrimSuffix(entry.Host, ".local.")
								log.Printf("DEBUG: Direct query resolved %s to IP %s (Host: %s)", name, ip, host)

								// Verify the hostname matches exactly
								if strings.EqualFold(host, name) {
									// Double check with reverse DNS
									if names, err := net.LookupAddr(ip); err == nil && len(names) > 0 {
										revHost := strings.TrimSuffix(names[0], ".local.")
										revHost = strings.TrimSuffix(revHost, ".")
										log.Printf("DEBUG: Reverse DNS for %s is %s", ip, revHost)

										// Only accept if reverse DNS matches too
										if strings.EqualFold(revHost, name) || strings.EqualFold(revHost, host) {
											directQueryIP = ip
											confirmedHost = name
											log.Printf("DEBUG: Confirmed hostname %s for IP %s with reverse DNS", confirmedHost, ip)

											s.mdnsMutex.Lock()
											s.mdnsNames[ip] = confirmedHost
											if _, exists := s.mdnsServices[ip]; !exists {
												s.mdnsServices[ip] = make(map[string]string)
											}
											s.mdnsMutex.Unlock()
										} else {
											log.Printf("DEBUG: Reverse DNS mismatch for %s: got %s, expected %s",
												ip, revHost, name)
										}
									}
								} else {
									log.Printf("DEBUG: Skipping mismatched hostname %s (expected %s) for IP %s",
										host, name, ip)
								}
							}
						}
						hostDone <- true
					}()

					// Query for the host directly
					hostParams := &mdns.QueryParam{
						Service:             fmt.Sprintf("%s.local.", name),
						Domain:              "local",
						Timeout:             time.Second * 2,
						Entries:             hostEntriesCh,
						WantUnicastResponse: true,
						DisableIPv6:         true,
					}

					if err := mdns.Query(hostParams); err != nil {
						log.Printf("Direct host query error for %s: %v", name, err)
					}
					close(hostEntriesCh)
					<-hostDone

					// Only proceed with service resolution if we have a confirmed host
					if confirmedHost == "" {
						log.Printf("DEBUG: Skipping service resolution for %s - no confirmed hostname", name)
						continue
					}

					// Now resolve this instance's service
					resolveEntriesCh := make(chan *mdns.ServiceEntry, 10)
					resolveDone := make(chan bool)

					// Start collecting resolution results
					go func() {
						for resolveEntry := range resolveEntriesCh {
							if resolveEntry != nil && resolveEntry.AddrV4 != nil {
								ip := resolveEntry.AddrV4.String()

								// Skip if this IP doesn't match our direct query result
								if directQueryIP != "" && ip != directQueryIP {
									log.Printf("DEBUG: Skipping mismatched IP %s for service %s (direct query gave %s)",
										ip, svcType, directQueryIP)
									continue
								}

								// Verify this is the host we're looking for
								if !strings.Contains(strings.ToLower(resolveEntry.Host), strings.ToLower(name)) &&
									!strings.Contains(strings.ToLower(resolveEntry.Name), strings.ToLower(name)) {
									log.Printf("DEBUG: Skipping mismatched host %s for service %s (expected %s)",
										resolveEntry.Host, svcType, name)
									continue
								}

								log.Printf("DEBUG: Resolved %s service %s to IP %s (Host: %s, Port: %d, Name: %s)",
									svcType, name, ip, resolveEntry.Host, resolveEntry.Port, resolveEntry.Name)

								s.mdnsMutex.Lock()
								// Store the name
								s.mdnsNames[ip] = name

								// Initialize services map for this IP if needed
								if _, exists := s.mdnsServices[ip]; !exists {
									s.mdnsServices[ip] = make(map[string]string)
								}

								// Store service info
								serviceInfo := fmt.Sprintf("Port: %d, Host: %s", resolveEntry.Port, resolveEntry.Host)
								if len(resolveEntry.InfoFields) > 0 {
									serviceInfo += fmt.Sprintf(", Info: %v", resolveEntry.InfoFields)
								}
								s.mdnsServices[ip][svcType] = serviceInfo
								s.mdnsMutex.Unlock()
							}
						}
						resolveDone <- true
					}()

					// Resolve the instance by querying the full service name
					params := &mdns.QueryParam{
						Service:             fmt.Sprintf("%s.%s", name, svcType),
						Domain:              "local",
						Timeout:             time.Second * 2, // Longer timeout for resolution
						Entries:             resolveEntriesCh,
						WantUnicastResponse: true,
						DisableIPv6:         true,
					}

					// Start resolution query
					if err := mdns.Query(params); err != nil {
						log.Printf("mDNS resolve error for %s instance %s: %v", svcType, name, err)
					}
					close(resolveEntriesCh)
					<-resolveDone
				}
			}
			done <- true
		}(service)

		// Start browse query in a goroutine
		go func() {
			params := &mdns.QueryParam{
				Service:             service,
				Domain:              "local",
				Timeout:             time.Second * 3, // Longer timeout for browsing
				Entries:             entriesCh,
				WantUnicastResponse: true,
				DisableIPv6:         true,
			}

			if err := mdns.Query(params); err != nil {
				log.Printf("mDNS browse error for %s: %v", service, err)
			}
			browseDone <- true
		}()

		// Wait for browse to complete
		<-browseDone
		close(entriesCh)
		<-done

		log.Printf("DEBUG: Browse complete for %s", service)
	}

	// Log what we found
	log.Printf("mDNS sweep complete - Found %d devices with names, %d with services",
		len(s.mdnsNames), len(s.mdnsServices))

	s.mdnsMutex.RLock()
	for ip, name := range s.mdnsNames {
		services := s.mdnsServices[ip]
		log.Printf("mDNS device: %s - Name: %s, Services: %v", ip, name, services)
	}
	s.mdnsMutex.RUnlock()
}

// ScanNetwork starts scanning the specified CIDR range
func (s *Scanner) ScanNetwork(cidr string, workers int) error {
	// Reset stop channel
	s.stopChan = make(chan struct{})

	// Disabled mDNS sweep for now
	// log.Printf("Starting mDNS sweep...")
	// s.sweepMDNS()
	// log.Printf("mDNS sweep complete, found %d devices with mDNS", len(s.mdnsNames))

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
		wg.Wait()
		remaining := atomic.LoadInt32(&s.sentCount) - atomic.LoadInt32(&s.scannedCount)
		if remaining > 0 {
			log.Printf("Found %d remaining IPs during completion", remaining)
			atomic.AddInt32(&s.scannedCount, remaining)
		}
		s.doneChan <- true
	}()

	return nil
}

func (s *Scanner) worker(id int, workChan chan net.IP, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() {
		s.statsLock.Lock()
		// Before removing worker, ensure we account for any remaining IPs
		remaining := atomic.LoadInt32(&s.sentCount) - atomic.LoadInt32(&s.scannedCount)
		if remaining > 0 {
			log.Printf("Worker %d found %d remaining IPs during cleanup", id, remaining)
			atomic.AddInt32(&s.scannedCount, remaining)
		}
		delete(s.workerStats, id)
		s.statsLock.Unlock()
	}()

	for ip := range workChan {
		select {
		case <-s.stopChan:
			return
		default:
			ipStr := ip.String()

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
				}

				if names, err := net.LookupAddr(ipStr); err == nil && len(names) > 0 {
					device.Hostname = names
				}

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

			// Increment the global scan counter for both online and offline devices
			atomic.AddInt32(&s.scannedCount, 1)

			// Update worker stats with completed count
			s.statsLock.Lock()
			if stat := s.workerStats[id]; stat != nil {
				// Only update stats every 10 IPs to reduce UI load
				if atomic.LoadInt32(&s.scannedCount)%10 == 0 {
					atomic.StoreInt32(&stat.IPsScanned, atomic.LoadInt32(&s.scannedCount))
					atomic.StoreInt32(&stat.TotalIPs, atomic.LoadInt32(&s.totalIPs))
					atomic.StoreInt32(&stat.SentCount, atomic.LoadInt32(&s.sentCount))
				}
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
	commonPorts := []int{80, 443, 22, 445, 8080, 3389, 5900} // Common ports that are often open

	// Create a channel for collecting results
	results := make(chan int, len(commonPorts))
	var wg sync.WaitGroup

	// Check ports concurrently
	for _, port := range commonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			log.Printf("Trying TCP port %d for %s", p, ip)
			d := net.Dialer{Timeout: time.Millisecond * 750} // Back to original timeout
			conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", ip, p))
			if err == nil {
				conn.Close()
				log.Printf("%s is reachable via TCP port %d", ip, p)
				results <- p
				isReachable = true
			}
		}(port)
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

	// Try a basic connection as last resort
	if !isReachable {
		d := net.Dialer{Timeout: time.Second * 1}
		conn, err := d.Dial("tcp", fmt.Sprintf("%s:7", ip)) // Try echo port as last resort
		if err == nil {
			conn.Close()
			log.Printf("%s is reachable via basic connection", ip)
			isReachable = true
		}
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
