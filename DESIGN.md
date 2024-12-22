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
