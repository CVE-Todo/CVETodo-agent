package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/CVE-Todo/CVETodo-agent/internal/config"
	"github.com/CVE-Todo/CVETodo-agent/internal/logger"
)

// Client handles communication with CVETodo API
type Client struct {
	baseURL    string
	apiKey     string
	teamID     string
	httpClient *http.Client
	logger     *logger.Logger
}

// Package represents a software package
type Package struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Type        string `json:"type"` // rpm, deb, pip, npm, etc.
	Arch        string `json:"architecture,omitempty"`
	Description string `json:"description,omitempty"`
}

// SystemInfo represents system information
type SystemInfo struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	OSVersion     string `json:"os_version"`
	Architecture  string `json:"architecture"`
	KernelVersion string `json:"kernel_version,omitempty"`
	LastScanTime  string `json:"last_scan_time"`
	AgentVersion  string `json:"agent_version"`
}

// ScanReport represents a vulnerability scan report
type ScanReport struct {
	AgentID       string     `json:"agent_id"`
	TeamID        string     `json:"team_id"`
	SystemInfo    SystemInfo `json:"system_info"`
	Packages      []Package  `json:"packages"`
	ScanTime      string     `json:"scan_time"`
	ScanType      string     `json:"scan_type"` // "full", "incremental"
	PendingReboot bool       `json:"pending_reboot"`
}

// APIError represents an API error response
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func (e APIError) Error() string {
	return fmt.Sprintf("API error %s: %s", e.Code, e.Message)
}

// New creates a new API client
func New(cfg *config.Config, logger *logger.Logger) *Client {
	timeout, err := time.ParseDuration(cfg.API.Timeout)
	if err != nil {
		timeout = 30 * time.Second
	}

	return &Client{
		baseURL: cfg.API.BaseURL,
		apiKey:  cfg.API.APIKey,
		teamID:  cfg.API.TeamID,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		logger: logger,
	}
}

// SubmitScanReport submits a scan report to the CVETodo API
func (c *Client) SubmitScanReport(report *ScanReport) error {
	c.logger.WithComponent("api").Info("submitting scan report")

	// Set team ID
	report.TeamID = c.teamID

	// Marshal report to JSON
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("failed to marshal scan report: %w", err)
	}

	// Make API request
	resp, err := c.makeRequest("POST", "/api/v1/agents/scans", data)
	if err != nil {
		return fmt.Errorf("failed to submit scan report: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		return c.handleErrorResponse(resp)
	}

	c.logger.WithComponent("api").Info("scan report submitted successfully")
	return nil
}

// RegisterAgent registers the agent with the CVETodo API
func (c *Client) RegisterAgent(systemInfo SystemInfo) error {
	c.logger.WithComponent("api").Info("registering agent")

	payload := map[string]interface{}{
		"team_id":     c.teamID,
		"system_info": systemInfo,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal registration request: %w", err)
	}

	// Make API request
	resp, err := c.makeRequest("POST", "/api/v1/agents/register", data)
	if err != nil {
		return fmt.Errorf("failed to register agent: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return c.handleErrorResponse(resp)
	}

	c.logger.WithComponent("api").Info("agent registered successfully")
	return nil
}

// makeRequest makes an HTTP request to the CVETodo API
func (c *Client) makeRequest(method, endpoint string, data []byte) (*http.Response, error) {
	url := c.baseURL + endpoint

	var body io.Reader
	if data != nil {
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("User-Agent", "CVETodo-Agent/1.0")

	// Make request
	start := time.Now()
	resp, err := c.httpClient.Do(req)
	duration := time.Since(start).Seconds() * 1000

	// Log performance - only if we have a response
	logData := map[string]interface{}{
		"method":   method,
		"endpoint": endpoint,
	}
	if resp != nil {
		logData["status"] = resp.StatusCode
	}
	c.logger.Performance("api_request", duration, logData)

	return resp, err
}

// handleErrorResponse handles API error responses
func (c *Client) handleErrorResponse(resp *http.Response) error {
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("API request failed with status %d", resp.StatusCode)
	}

	var apiErr APIError
	if err := json.Unmarshal(body, &apiErr); err != nil {
		return fmt.Errorf("API request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return apiErr
}
