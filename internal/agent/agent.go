package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/CVE-Todo/CVETodo-agent/internal/api"
	"github.com/CVE-Todo/CVETodo-agent/internal/config"
	"github.com/CVE-Todo/CVETodo-agent/internal/logger"
	"github.com/CVE-Todo/CVETodo-agent/internal/scanner"
)

// Agent represents the main CVETodo agent
type Agent struct {
	config    *config.Config
	logger    *logger.Logger
	apiClient *api.Client
	scanner   *scanner.Manager
	ctx       context.Context
	cancel    context.CancelFunc
}

// New creates a new CVETodo agent instance
func New(cfg *config.Config, log *logger.Logger) *Agent {
	ctx, cancel := context.WithCancel(context.Background())

	return &Agent{
		config:    cfg,
		logger:    log,
		apiClient: api.New(cfg, log),
		scanner:   scanner.New(cfg, log),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Run starts the agent in continuous monitoring mode
func (a *Agent) Run() error {
	a.logger.WithComponent("agent").Info("starting CVETodo agent")

	// If disabled via config, idle without scanning so the service can stay
	// installed while performing no work until re-enabled
	if !a.config.Agent.Enabled {
		a.logger.WithComponent("agent").Warn("agent is disabled (agent.enabled: false); no scans will run until re-enabled")

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		select {
		case <-a.ctx.Done():
		case <-sigChan:
		}
		return nil
	}

	// Ensure data directory exists
	if err := a.ensureDataDir(); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Register agent with API
	systemInfo := a.scanner.GetSystemInfo()
	if err := a.apiClient.RegisterAgent(systemInfo); err != nil {
		a.logger.WithComponent("agent").WithError(err).Warn("failed to register agent")
	}

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start scan ticker
	scanTicker := time.NewTicker(a.config.Agent.ScanInterval)
	defer scanTicker.Stop()

	// Start report ticker
	reportTicker := time.NewTicker(a.config.Agent.ReportInterval)
	defer reportTicker.Stop()

	// Perform initial scan
	if err := a.performScan(); err != nil {
		a.logger.WithComponent("agent").WithError(err).Error("initial scan failed")
	}

	// Main event loop
	for {
		select {
		case <-a.ctx.Done():
			a.logger.WithComponent("agent").Info("agent context cancelled")
			return nil

		case sig := <-sigChan:
			a.logger.WithComponent("agent").WithField("signal", sig.String()).Info("received signal, shutting down")
			a.cancel()
			return nil

		case <-scanTicker.C:
			a.logger.WithComponent("agent").Info("performing scheduled scan")
			if err := a.performScan(); err != nil {
				a.logger.WithComponent("agent").WithError(err).Error("scheduled scan failed")
			}

		case <-reportTicker.C:
			a.logger.WithComponent("agent").Info("performing scheduled report")
			if err := a.submitStoredReports(); err != nil {
				a.logger.WithComponent("agent").WithError(err).Error("scheduled report failed")
			}
		}
	}
}

// Scan performs a one-time system scan
func (a *Agent) Scan() error {
	a.logger.WithComponent("agent").Info("performing one-time scan")

	// Ensure data directory exists
	if err := a.ensureDataDir(); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Register agent with API
	systemInfo := a.scanner.GetSystemInfo()
	if err := a.apiClient.RegisterAgent(systemInfo); err != nil {
		a.logger.WithComponent("agent").WithError(err).Warn("failed to register agent")
	}

	// Perform scan
	return a.performScan()
}

// performScan executes a vulnerability scan
func (a *Agent) performScan() error {
	start := time.Now()
	a.logger.WithComponent("agent").Info("starting package scan")

	// Get system information
	systemInfo := a.scanner.GetSystemInfo()
	systemInfo.LastScanTime = time.Now().Format(time.RFC3339)

	// Scan for packages
	packages, err := a.scanner.ScanAllPackages()
	if err != nil {
		return fmt.Errorf("package scan failed: %w", err)
	}

	a.logger.WithComponent("agent").WithField("package_count", len(packages)).Info("package scan completed")

	// Check for pending reboot
	pendingReboot := a.scanner.GetPendingReboot()
	if pendingReboot {
		a.logger.WithComponent("agent").Info("pending reboot detected")
	}

	// Create scan report
	report := &api.ScanReport{
		AgentID:       systemInfo.Hostname, // TODO: Generate unique agent ID
		SystemInfo:    systemInfo,
		Packages:      packages,
		ScanTime:      time.Now().Format(time.RFC3339),
		ScanType:      "full",
		PendingReboot: pendingReboot,
	}

	// Submit scan report
	if err := a.apiClient.SubmitScanReport(report); err != nil {
		a.logger.WithComponent("agent").WithError(err).Error("failed to submit scan report, storing for later")
		return a.storeScanReport(systemInfo, packages, "full")
	}

	duration := time.Since(start)
	a.logger.Performance("package_scan", duration.Seconds()*1000, map[string]interface{}{
		"packages": len(packages),
	})

	a.logger.WithComponent("agent").WithField("duration", duration).WithField("packages", len(packages)).Info("scan completed and submitted successfully")
	return nil
}

// storeScanReport stores a scan report locally for later submission
func (a *Agent) storeScanReport(systemInfo api.SystemInfo, packages []api.Package, scanType string) error {
	// Check for pending reboot
	pendingReboot := a.scanner.GetPendingReboot()

	report := &api.ScanReport{
		AgentID:       systemInfo.Hostname,
		SystemInfo:    systemInfo,
		Packages:      packages,
		ScanTime:      time.Now().Format(time.RFC3339),
		ScanType:      scanType,
		PendingReboot: pendingReboot,
	}

	// Store report in data directory
	filename := fmt.Sprintf("scan_%s.json", time.Now().Format("20060102_150405"))
	filepath := filepath.Join(a.config.Agent.DataDir, filename)

	// Reports contain the full software inventory of this host; keep them
	// readable only by the agent's user
	file, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create report file: %w", err)
	}

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		_ = file.Close()
		return fmt.Errorf("failed to encode report: %w", err)
	}

	// Close errors matter here: they can signal the report never made it to disk
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to write report file: %w", err)
	}

	a.logger.WithComponent("agent").WithField("file", filepath).Info("scan report stored locally")
	return nil
}

// submitStoredReports submits any stored scan reports
func (a *Agent) submitStoredReports() error {
	pattern := filepath.Join(a.config.Agent.DataDir, "scan_*.json")
	files, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("failed to find stored reports: %w", err)
	}

	if len(files) == 0 {
		a.logger.WithComponent("agent").Debug("no stored reports to submit")
		return nil
	}

	a.logger.WithComponent("agent").WithField("count", len(files)).Info("submitting stored reports")

	var submitted int
	for _, filename := range files {
		if err := a.submitStoredReport(filename); err != nil {
			a.logger.WithComponent("agent").WithField("file", filename).WithError(err).Error("failed to submit stored report")
			continue
		}
		submitted++
	}

	a.logger.WithComponent("agent").WithField("submitted", submitted).Info("stored reports submission completed")
	return nil
}

// submitStoredReport submits a single stored report and removes the file on success
func (a *Agent) submitStoredReport(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open report file: %w", err)
	}
	defer func() { _ = file.Close() }()

	var report api.ScanReport
	if err := json.NewDecoder(file).Decode(&report); err != nil {
		return fmt.Errorf("failed to decode report: %w", err)
	}

	// Submit report
	if err := a.apiClient.SubmitScanReport(&report); err != nil {
		return fmt.Errorf("failed to submit report: %w", err)
	}

	// Remove file on successful submission
	if err := os.Remove(filename); err != nil {
		a.logger.WithComponent("agent").WithField("file", filename).WithError(err).Warn("failed to remove submitted report file")
	}

	a.logger.WithComponent("agent").WithField("file", filename).Info("stored report submitted and removed")
	return nil
}

// ensureDataDir creates the data directory if it doesn't exist. The
// directory holds queued scan reports (full software inventories), so it
// is restricted to the agent's user.
func (a *Agent) ensureDataDir() error {
	return os.MkdirAll(a.config.Agent.DataDir, 0700)
}

// Stop gracefully stops the agent
func (a *Agent) Stop() {
	a.logger.WithComponent("agent").Info("stopping agent")
	a.cancel()
}
