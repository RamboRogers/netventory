<p align="center">
<table align="center">
  <tr>
    <td align="center" width="50%"><strong>Terminal Interface</strong></td>
    <td align="center" width="50%"><strong>Web Interface</strong></td>
  </tr>
  <tr>
    <td align="center"><img src="media/demo.gif" width="100%" alt="Terminal Interface Demo"></td>
    <td align="center"><img src="media/demoweb.gif" width="100%" alt="Web Interface Demo"></td>
  </tr>
  <tr>
    <td align="center" width="50%"><strong>Mac Interface</strong></td>
    <td align="center" width="50%"><strong>Mac Scan Interface</strong></td>
  </tr>
  <tr>
    <td align="center"><img src="media/mac1.png" width="100%" alt="GUI Interface Demo"></td>
    <td align="center"><img src="media/mac3.png" width="100%" alt="Web Interface Demo"></td>
  </tr>
</table>

<div align="center">
  <h1>NetVentory</h1>
  <p><strong>Network Discovery Tool</strong></p>
  <p>🚀 Single binary | 🌍 Multiplatform | ⚡ Fast | 🎨 Beautiful | 🌐 Web | 📺 TUI | 🍎 Mac</p>
  <p>
    <img src="https://img.shields.io/badge/version-0.4.0n-blue.svg" alt="Version 0.2.0n">
    <img src="https://img.shields.io/badge/go-%3E%3D1.21-00ADD8.svg" alt="Go Version">
    <img src="https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-brightgreen.svg" alt="Platform Support">
    <img src="https://img.shields.io/badge/license-GPLv3-green.svg" alt="License">
  </p>
</div>

NetVentory is a fast, beautiful network discovery tool with both terminal and web interfaces. It provides detailed device information, port scanning, and real-time monitoring without requiring root privileges.

NetVentory is a powerful yet intuitive network discovery tool that provides comprehensive visibility into your network infrastructure. With its user-friendly interfaces and robust feature set, it makes network exploration and monitoring accessible to both novice users and experienced administrators.

### 2025-04-20

- Paid for Apple Developer Account and created a Mac App with Signature!

## 🌟 Features

### Discovery
- Fast network scanning with configurable worker count
- Automatic interface detection and CIDR range calculation
- MAC address resolution and vendor lookup
- Port scanning (22, 80, 443, 445, 139, 135, 8080, 3389, 5900, 8006)
- Advanced hostname resolution:
  - DNS resolution
  - NetBIOS name resolution
  - SMB hostname discovery
  - RDP certificate extraction
  - mDNS/Bonjour discovery
- Device type detection (Apple, Windows, etc.)
- No root privileges required

### Terminal Interface
- Beautiful animated UI with real-time updates
- Network interface selection with auto-detection
- Live scanning progress and worker monitoring
- Detailed device information view
- Interactive device list with navigation
- Debug mode for detailed logging

### Web Interface
- Secure access with token authentication
- Dark-themed responsive design
- Real-time updates via WebSocket
- Network interface selection
- CIDR range configuration
- Live scanning progress
- Sortable device list
- Detailed device views
- Export functionality
- Worker monitoring

### Security & Privacy
- Token-based authentication for web access
- No sensitive data collection
- Privacy-focused design

### Performance
- Concurrent scanning with worker pools
- Non-blocking operations
- Memory-efficient device tracking
- Real-time progress updates
- Cross-platform support

## ⚡ Installation

The binary is available for Windows, Mac, and Linux. You can download from the bins folder, or use the install scripts. They are in the repo if you want to browse the commands (super simple download and copy).

### 🐧 Mac & Linux

Open a terminal and run the following command:

```bash
curl -L https://raw.githubusercontent.com/RamboRogers/netventory/refs/heads/master/install.sh | sh
```

or Brew for the Command Line Mac

```bash
brew tap ramborogers/netventory
brew install netventory
```

or for the GUI Mac

```bash
brew tap ramborogers/netventory
brew install --cask netventory
```

### 🪟 Windows PowerShell

Open a PowerShell terminal and run the following command:
```powershell
iwr -useb https://raw.githubusercontent.com/RamboRogers/netventory/refs/heads/master/install.ps1 | iex
```


## 🚀 Usage

NetVentory offers several command-line options:

```bash
# Standard Terminal Usage
netventory              # Start with terminal interface
netventory -d          # Enable debug mode (generates debug.log)
netventory --debug     # Same as -d

# Web Interface
netventory -w          # Start web interface
netventory --web       # Same as -w
netventory -p 8080    # Set web interface port (default: 7331)
netventory --port 8080 # Same as -p

# Performance
netventory --workers 100 # Set number of scanning workers (default: 50)

# Information
netventory -v          # Display version information
netventory --version   # Same as -v
netventory -h          # Show help message
```

When using the web interface (-w), access it at:
```
http://localhost:7331?auth=<token>
```
The authentication token is generated and displayed when starting the web interface.

## 💡 Use Cases
- **Network Auditing**: Quick network device discovery
- **Security Assessment**: Port and service enumeration
- **Network Management**: Device inventory and tracking
- **Troubleshooting**: Network connectivity verification

### Screenshots TUI GUI


<div align="center">
  <table>
    <tr>
      <td><img src="media/screenshot2.png" alt="NetVentory Interface Selection" width="400"/></td>
      <td><img src="media/screenshot3.png" alt="NetVentory Network Selection" width="400"/></td>
    </tr>
    <tr>
      <td><img src="media/screenshot4.png" alt="NetVentory Scanning" width="400"/></td>
      <td><img src="media/screenshot5.png" alt="NetVentory Device Details" width="400"/></td>
    </tr>
  </table>
</div>

### Screenshots Web GUI

<div align="center">
  <table>
    <tr>
      <td><img src="media/screenshot6.png" alt="NetVentory Interface Selection" width="400"/></td>
      <td><img src="media/screenshot7.png" alt="NetVentory Network Selection" width="400"/></td>
    </tr>
    <tr>
      <td><img src="media/screenshot8.png" alt="NetVentory Scanning" width="400"/></td>
      <td><img src="media/screenshot9.png" alt="NetVentory Device Details" width="400"/></td>
    </tr>
  </table>
</div>



<div align="center">

## ⚖️ License

<p>
NetVentory is licensed under the GNU General Public License v3.0 (GPLv3).<br>
<em>Free Software</em>
</p>

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge)](https://www.gnu.org/licenses/gpl-3.0)

### Connect With Me 🤝

[![GitHub](https://img.shields.io/badge/GitHub-RamboRogers-181717?style=for-the-badge&logo=github)](https://github.com/RamboRogers)
[![Twitter](https://img.shields.io/badge/Twitter-@rogerscissp-1DA1F2?style=for-the-badge&logo=twitter)](https://x.com/rogerscissp)
[![Website](https://img.shields.io/badge/Web-matthewrogers.org-00ADD8?style=for-the-badge&logo=google-chrome)](https://matthewrogers.org)

![RamboRogers](media/ramborogers.png)

</div>

## 🚀 What's New in v0.2.0n

### Complete Web Interface
- Beautiful dark-themed responsive UI
- Real-time scanning updates via WebSocket
- Secure authentication with unique tokens
- Network interface auto-detection
- CIDR range configuration and validation
- Live progress tracking and worker monitoring
- Sortable device list with detailed views
- Export functionality for scan results
- Access via `http://localhost:7331?auth=<token>`

### Performance Improvements
- Enhanced concurrent scanning
- Improved memory efficiency
- Better cross-platform support
- Real-time progress updates
- Optimized worker management

## 🎯 What's New in v0.3.0n

### Enhanced Device Discovery
- Advanced hostname resolution with multiple methods:
  - NetBIOS name resolution for Windows devices
  - SMB hostname discovery with guest/anonymous access
  - RDP certificate hostname extraction
  - mDNS/Bonjour discovery for Apple devices
- Improved device type detection:
  - Apple device detection via vendor, ports, and mDNS
  - Windows device detection via SMB and NetBIOS
- Added Proxmox port detection (8006)

### Hostname Resolution Improvements
- Multi-layered hostname resolution strategy
- Fallback mechanisms when primary methods fail
- Concurrent resolution for faster results
- Hostname validation and cleaning
- Support for multiple hostnames per device

### Protocol-Specific Enhancements
- SMB improvements:
  - Guest account support
  - Anonymous access fallback
  - Share enumeration
  - UNC path parsing
- RDP enhancements:
  - TLS certificate parsing
  - Multiple security protocol support
  - Common Name and SAN extraction
- mDNS features:
  - Service type discovery
  - Apple-specific service detection
  - Reduced timeouts for faster scanning

### Performance Optimizations
- Concurrent hostname resolution
- Optimized timeout values
- Improved error handling
- Enhanced progress tracking
- Better memory management

### UI Improvements
- Protocol-specific links in device details
- Enhanced port information display
- Improved device type indicators
- Better progress feedback