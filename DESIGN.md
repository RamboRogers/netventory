# NetVentory Design Document

## Overview
NetVentory is a terminal-based network discovery tool designed to provide fast, efficient network scanning with a beautiful user interface. It operates without requiring root privileges and supports cross-platform functionality.

## Core Features
1. Network Discovery
   - Automatic interface detection
   - CIDR range support
   - Concurrent scanning with configurable workers
   - Multiple detection methods (TCP, UDP, ARP)
   - Port scanning (22, 80, 443, 445, 139, 135, 8080, 3389, 5900)
   - MAC address resolution
   - Hostname resolution
   - Future: mDNS, service discovery

2. User Interface
   - Animated welcome screen
   - Network interface selection
   - Real-time progress tracking
   - Device list with details
   - Worker status monitoring
   - Debug logging support

3. Command Line Interface
   - Debug mode (-debug)
   - Worker count configuration (-w)
   - Help text and usage information
   - Report generation

## Architecture

### Main Components
1. Model (netventory.go)
   - Application state management
   - Screen transitions
   - User input handling
   - View coordination

2. Scanner Package
   - Network scanning (scanner.go)
   - MAC address resolution (mac.go)
   - Worker pool management
   - Device discovery
   - Port scanning

3. Views Package
   - Welcome screen (welcome.go)
   - Interface selection (interfaces.go)
   - Scanning progress (scanning.go)
   - Device details (device_details.go)
   - Styles and theming (styles.go)

### Data Structures

1. Device
```go
type Device struct {
    IPAddress  string
    Hostname   string
    MACAddress string
    Vendor     string
    Status     string
    Ports      []int
}
```

2. Scanner
```go
type Scanner struct {
    debug        bool
    workerCount  int
    devices      map[string]Device
    workerStats  map[int]*WorkerStatus
    resultsChan  chan Device
    doneChan     chan bool
}
```

3. WorkerStatus
```go
type WorkerStatus struct {
    ID          int
    IPsScanned  int32
    CurrentIP   string
    LastUpdate  time.Time
}
```

### Discovery Process
1. Interface Selection
   - List available network interfaces
   - Auto-detect default route
   - Parse CIDR range

2. Scanning
   - Initialize worker pool
   - Distribute IP ranges
   - Concurrent port scanning
   - MAC address resolution
   - Hostname lookup
   - Real-time progress updates

3. Result Processing
   - Device information collection
   - Status updates
   - Report generation
   - UI updates

## Design Principles
1. Non-root Operation
   - Use unprivileged scanning methods
   - Fallback mechanisms for privileged operations

2. Performance
   - Concurrent scanning
   - Efficient resource usage
   - Non-blocking operations

3. User Experience
   - Real-time feedback
   - Clear progress indication
   - Responsive interface
   - Informative error messages

4. Cross-platform
   - Platform-independent code
   - OS-specific optimizations
   - Consistent behavior

## Future Enhancements
1. Network Analysis
   - Device fingerprinting
   - Service version detection
   - Network topology mapping
   - Traffic analysis

2. Reporting
   - Enhanced report formats
   - Export options
   - Historical comparison

3. Integration
   - API endpoints
   - Plugin system
   - External tool integration

## Device Discovery

### Hostname Resolution

NetVentory employs multiple methods to resolve device hostnames, attempting each method in order of reliability and efficiency:

### 1. DNS Resolution
- Primary method using `net.LookupAddr`
- Returns FQDN when available
- Fast and reliable for configured hosts
- No additional network overhead

### 2. SSH Banner Resolution (Port 22)
- Parses SSH server banners for embedded hostnames
- Common formats:
  - `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5`
  - `SSH-2.0-OpenSSH_7.4 SERVERNAME`
  - `SSH-2.0-OpenSSH_8.9p1 debian.example.com`
- Filters out common software and OS names
- Very fast (single packet exchange)
- No authentication required

### 3. NetBIOS Name Resolution (Port 137)
- Uses UDP port 137 for name queries
- Sends status query to retrieve all registered names
- Name types and flags:
  - Type 0x00: Workstation Service
  - Type 0x20: File Server Service
  - Flags 0x0400: Registered unique name
  - Flags 0x8000: Group name (ignored)
- Prioritizes machine names over workgroup names
- Two-pass approach:
  1. Look for machine names (flags 0x0400)
  2. Fall back to any non-group name
- Fast (UDP) and requires no authentication
- Common on Windows systems

### 4. SMB Hostname Resolution (Port 445)
- Attempts connection with different credentials:
  1. Guest account (most compatible)
  2. Empty credentials (fallback)
- Extracts hostname from share list
- Parses UNC paths (e.g., `\\HOSTNAME\share`)
- More reliable but slower than NetBIOS
- Requires TCP connection and session setup

### 5. RDP Hostname Resolution (Port 3389)
- Uses RDP protocol negotiation
- Supports multiple security protocols:
  - Standard RDP (0x01)
  - TLS (0x02)
  - CredSSP (0x04)
- Extracts hostname from SSL/TLS certificates:
  1. DNS Names
  2. Common Name
  3. Organization Name
  4. Subject Alternative Names
- Handles self-signed certificates
- Most complex but can work when other methods fail

### 6. mDNS Resolution
- Uses multicast DNS for local network discovery
- Provides additional service information
- Complements other resolution methods
- Limited to mDNS-enabled devices

### Resolution Priority
1. Try DNS lookup first (fastest, most reliable)
2. If DNS fails, try protocol-specific methods based on open ports:
   - Port 22: SSH banner resolution
   - Port 137/445: NetBIOS then SMB resolution
   - Port 3389: RDP certificate resolution
3. Use mDNS data if available
4. Fall back to IP-only if no hostname found

### Hostname Validation
- Enforces RFC-compliant hostnames:
  - 2-63 characters long
  - Starts with letter
  - Ends with letter or digit
  - Contains only letters, digits, and hyphens
  - No special characters or spaces
- Cleans and normalizes hostnames:
  - Removes port numbers
  - Takes first part of FQDN
  - Strips invalid characters
  - Preserves case

### Design Principles
- Minimize network impact
- Graceful fallbacks
- Respect timeouts (500ms-2s)
- Handle errors without blocking
- Clean and normalize hostnames
- Support multiple resolution methods
- Detailed logging for troubleshooting

## Scan Management

### Scan Lifecycle
1. Initialization
   - Create scanner instance with debug mode setting
   - Initialize device maps and channels
   - Set up worker statistics tracking
   - Configure timeouts and worker count

2. Active Scanning
   - Concurrent worker management
   - Progress tracking per worker
   - Real-time device updates
   - Safe state management with mutexes
   - Graceful cancellation support

3. Scan Completion
   - Wait for all workers to finish
   - Process remaining results
   - Clean up resources
   - Send final updates

### Error Handling and Recovery

#### Scanner State Management
- Mutex protection for shared resources:
  ```go
  deviceMutex  sync.RWMutex    // Protects device map
  scanMutex    sync.RWMutex    // Protects scan state
  clientsMutex sync.RWMutex    // Protects WebSocket clients
  writeMutex   sync.Map        // Per-connection write protection
  ```

#### Safe Scan Operations
1. Starting a Scan
   - Check for existing scan
   - Create new scanner instance
   - Reset device list
   - Initialize worker stats
   - Handle initialization failures

2. Stopping a Scan
   - Signal workers to stop
   - Wait for cleanup
   - Update scan state
   - Notify clients

3. Dumping Scan Data
   - Stop any active scan first
   - Clear device data safely
   - Reset scanner state
   - Clean up worker stats
   - Send clear notifications

#### Worker Management
- Track worker status:
  ```go
  type WorkerStatus struct {
      StartTime  time.Time
      LastSeen   time.Time
      CurrentIP  string
      State      string
      IPsFound   int32
      IPsScanned int32
      TotalIPs   int32
  }
  ```

- Safe worker cleanup:
  - Account for remaining IPs
  - Update scan statistics
  - Remove worker stats
  - Close channels

#### WebSocket Communication
- Per-connection write mutex
- Safe client disconnection
- Broadcast error handling
- Connection state tracking

### Recovery Mechanisms
1. Scanner Creation Failure
   ```go
   if s.scanner == nil {
       s.scanActive = false
       return fmt.Errorf("failed to create scanner")
   }
   ```

2. Worker Cleanup
   ```go
   defer func() {
       s.scanMutex.Lock()
       s.scanActive = false
       s.scanMutex.Unlock()
   }()
   ```

3. Safe State Updates
   ```go
   s.scanMutex.Lock()
   s.scanActive = false
   s.scanner = nil
   s.scanMutex.Unlock()
   ```

4. Progress Tracking
   ```go
   remaining := atomic.LoadInt32(&s.sentCount) - atomic.LoadInt32(&s.scannedCount)
   if remaining > 0 {
       atomic.AddInt32(&s.scannedCount, remaining)
   }
   ```

### Design Principles
- Always protect shared state with appropriate locks
- Use atomic operations for counters
- Clean up resources in reverse order of creation
- Handle partial failures gracefully
- Provide clear error messages
- Maintain consistent state
- Prevent resource leaks
- Support concurrent operations safely
