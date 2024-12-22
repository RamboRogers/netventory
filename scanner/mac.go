package scanner

import (
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// GetMACFromIP attempts to get the MAC address for an IP using TCP/UDP connections
func GetMACFromIP(ip string) string {
	// Try to connect to common ports to trigger ARP
	commonPorts := []int{80, 443, 22, 445, 139, 135, 8080, 3389, 5900}
	for _, port := range commonPorts {
		d := net.Dialer{Timeout: time.Millisecond * 100}
		conn, err := d.Dial("tcp", fmt.Sprintf("%s:%d", ip, port))
		if err == nil {
			conn.Close()
		}
	}

	// Try UDP to trigger ARP
	udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:137", ip))
	if err == nil {
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err == nil {
			conn.Write([]byte{0})
			conn.Close()
		}
	}

	// Give ARP time to populate
	time.Sleep(time.Millisecond * 100)

	// Query ARP table based on OS
	switch runtime.GOOS {
	case "darwin", "linux":
		cmd := exec.Command("arp", "-n", ip)
		output, err := cmd.Output()
		if err == nil {
			// Extract MAC from arp output using regex
			re := regexp.MustCompile(`([0-9A-Fa-f]{1,2}[:-]){5}([0-9A-Fa-f]{1,2})`)
			if mac := re.FindString(string(output)); mac != "" {
				log.Printf("DEBUG: Found MAC %s for IP %s using arp -n", mac, ip)
				return NormalizeMACAddress(mac)
			}
		}
	case "windows":
		cmd := exec.Command("arp", "-a", ip)
		output, err := cmd.Output()
		if err == nil {
			// Extract MAC from arp output using regex
			re := regexp.MustCompile(`([0-9A-Fa-f]{1,2}-){5}([0-9A-Fa-f]{1,2})`)
			if mac := re.FindString(string(output)); mac != "" {
				log.Printf("DEBUG: Found MAC %s for IP %s using arp -a", mac, ip)
				return NormalizeMACAddress(mac)
			}
		}
	}

	return ""
}

// NormalizeMACAddress converts a MAC address to a standard format
func NormalizeMACAddress(mac string) string {
	// Convert to uppercase
	mac = strings.ToUpper(mac)

	// Remove any separators
	mac = strings.ReplaceAll(mac, ":", "")
	mac = strings.ReplaceAll(mac, "-", "")
	mac = strings.ReplaceAll(mac, ".", "")

	// Insert colons every 2 characters
	var result strings.Builder
	for i, char := range mac {
		if i > 0 && i%2 == 0 {
			result.WriteRune(':')
		}
		result.WriteRune(char)
	}

	return result.String()
}

// LookupVendor looks up the vendor for a MAC address
func LookupVendor(mac string) string {
	// Normalize MAC address format
	mac = NormalizeMACAddress(mac)
	if mac == "" {
		return "Unknown"
	}

	// TODO: Implement OUI lookup from IEEE database
	return "Unknown Vendor"
}
