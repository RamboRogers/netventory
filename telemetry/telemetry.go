// Package telemetry handles anonymous usage statistics and version authorization
package telemetry

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"
)

const (
	apiEndpoint    = "/api"
	healthEndpoint = "/health"
	authHeader     = "X-API-Token"
)

// CheckinRequest represents the API request structure
type CheckinRequest struct {
	SystemID string `json:"system_id"`
	Version  string `json:"version"`
	Token    string `json:"token"`
}

// CheckinResponse represents the API response structure
type CheckinResponse struct {
	Authorized int    `json:"authorized"`
	Timestamp  string `json:"timestamp"`
}

// HealthResponse represents the health check response
type HealthResponse struct {
	Status string `json:"status"`
}

// Client represents a telemetry client
type Client struct {
	token     string
	version   string
	systemID  string
	serverURL string
	stopChan  chan struct{}
	waitGroup sync.WaitGroup
	client    *http.Client
}

// NewClient creates a new telemetry client
func NewClient(serverURL, token, version string) (*Client, error) {
	return &Client{
		token:     token,
		version:   version,
		serverURL: serverURL,
		systemID:  generateSystemID(),
		stopChan:  make(chan struct{}),
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// Start begins telemetry collection and periodic check-ins
func (c *Client) Start() error {
	// Check server health first
	if err := c.checkHealth(); err != nil {
		return fmt.Errorf("health check failed: %v", err)
	}

	// Initial authorization check
	authorized, err := c.CheckAuthorization()
	if err != nil {
		return fmt.Errorf("authorization check failed: %v", err)
	}
	if !authorized {
		return fmt.Errorf("version %s is not authorized", c.version)
	}

	// Start periodic check-ins
	c.waitGroup.Add(1)
	go c.periodicCheckIn()

	return nil
}

// Stop halts telemetry collection
func (c *Client) Stop() {
	close(c.stopChan)
	c.waitGroup.Wait()
}

// checkHealth verifies the telemetry service is available
func (c *Client) checkHealth() error {
	req, err := http.NewRequest("GET", c.serverURL+healthEndpoint, nil)
	if err != nil {
		return err
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed with status: %d", resp.StatusCode)
	}

	var health HealthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		return err
	}

	if health.Status != "healthy" {
		return fmt.Errorf("unhealthy service status: %s", health.Status)
	}

	return nil
}

// CheckAuthorization verifies if the current version is authorized
func (c *Client) CheckAuthorization() (bool, error) {
	request := CheckinRequest{
		SystemID: c.systemID,
		Version:  c.version,
		Token:    c.token,
	}

	jsonData, err := json.Marshal(request)
	if err != nil {
		return false, err
	}

	req, err := http.NewRequest("POST", c.serverURL+apiEndpoint, bytes.NewBuffer(jsonData))
	if err != nil {
		return false, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(authHeader, c.token)

	resp, err := c.client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("authorization failed with status: %d", resp.StatusCode)
	}

	var result CheckinResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, err
	}

	// Parse timestamp if needed, but don't fail if it can't be parsed
	if _, err := time.Parse("2006-01-02T15:04:05.999999", result.Timestamp); err != nil {
		log.Printf("Warning: Could not parse timestamp %q: %v", result.Timestamp, err)
	}

	return result.Authorized == 1, nil
}

// periodicCheckIn sends telemetry data every hour
func (c *Client) periodicCheckIn() {
	defer c.waitGroup.Done()

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if authorized, err := c.CheckAuthorization(); err != nil {
				fmt.Fprintf(os.Stderr, "Telemetry check-in error: %v\n", err)
			} else if !authorized {
				fmt.Fprintf(os.Stderr, "Version %s is no longer authorized\n", c.version)
				// Optionally handle unauthorized version (e.g., graceful shutdown)
			}
		case <-c.stopChan:
			return
		}
	}
}

// generateSystemID creates a unique anonymous identifier
func generateSystemID() string {
	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Get executable path
	exe, err := os.Executable()
	if err != nil {
		exe = "unknown"
	}

	// Create hash from hostname and executable path
	h := sha256.New()
	io.WriteString(h, hostname)
	io.WriteString(h, exe)
	io.WriteString(h, runtime.GOOS)
	io.WriteString(h, runtime.GOARCH)

	return fmt.Sprintf("%x", h.Sum(nil))[:32]
}
