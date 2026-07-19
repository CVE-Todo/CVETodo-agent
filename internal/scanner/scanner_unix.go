//go:build !windows
// +build !windows

package scanner

import (
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/CVE-Todo/CVETodo-agent/internal/api"
	"github.com/CVE-Todo/CVETodo-agent/internal/config"
	"github.com/CVE-Todo/CVETodo-agent/internal/logger"
)

// Scanner interface defines package scanning methods
type Scanner interface {
	Name() string
	IsAvailable() bool
	ScanPackages() ([]api.Package, error)
}

// Manager manages multiple package scanners
type Manager struct {
	scanners []Scanner
	logger   *logger.Logger
	config   *config.Config
}

// New creates a new scanner manager
func New(cfg *config.Config, logger *logger.Logger) *Manager {
	manager := &Manager{
		config: cfg,
		logger: logger,
	}

	// Initialize available scanners
	manager.initializeScanners()

	return manager
}

// initializeScanners initializes all available package scanners
func (m *Manager) initializeScanners() {
	// Available scanner types
	allScanners := map[string]func() Scanner{
		"dpkg": func() Scanner { return NewDpkgScanner(m.logger) },
		"rpm":  func() Scanner { return NewRpmScanner(m.logger) },
		"pip":  func() Scanner { return NewPipScanner(m.logger) },
		"npm":  func() Scanner { return NewNpmScanner(m.logger) },
	}

	// Add enabled and available scanners
	for _, scannerName := range m.config.Scanner.EnabledScanners {
		if scannerFactory, exists := allScanners[scannerName]; exists {
			scanner := scannerFactory()
			if scanner.IsAvailable() {
				m.scanners = append(m.scanners, scanner)
				m.logger.WithComponent("scanner").WithField("scanner", scannerName).Info("scanner enabled")
			} else {
				m.logger.WithComponent("scanner").WithField("scanner", scannerName).Warn("scanner not available on this system")
			}
		}
	}
}

// ScanAllPackages scans for packages using all available scanners
func (m *Manager) ScanAllPackages() ([]api.Package, error) {
	m.logger.WithComponent("scanner").Info("starting package scan")

	var allPackages []api.Package

	// Add OS as a package
	osVersion := getOSVersion()
	kernelVersion := getKernelVersion()

	osPackage := api.Package{
		Name:        osVersion,
		Version:     kernelVersion,
		Type:        "os",
		Description: "Operating System",
	}
	allPackages = append(allPackages, osPackage)

	m.logger.WithComponent("scanner").
		WithField("name", osVersion).
		WithField("version", kernelVersion).
		Info("added OS package")

	for _, scanner := range m.scanners {
		m.logger.WithComponent("scanner").WithField("scanner", scanner.Name()).Info("running scanner")

		packages, err := scanner.ScanPackages()
		if err != nil {
			m.logger.WithComponent("scanner").WithField("scanner", scanner.Name()).WithError(err).Error("scanner failed")
			continue
		}

		m.logger.WithComponent("scanner").
			WithField("scanner", scanner.Name()).
			WithField("package_count", len(packages)).
			Info("scanner completed")

		allPackages = append(allPackages, packages...)
	}

	m.logger.WithComponent("scanner").
		WithField("total_packages", len(allPackages)).
		Info("package scan completed")

	return allPackages, nil
}

// GetSystemInfo retrieves system information
func (m *Manager) GetSystemInfo() api.SystemInfo {
	hostname, _ := os.Hostname()

	return api.SystemInfo{
		Hostname:      hostname,
		OS:            runtime.GOOS,
		OSVersion:     getOSVersion(),
		Architecture:  runtime.GOARCH,
		KernelVersion: getKernelVersion(),
		AgentVersion:  "1.0.0", // TODO: Get from build info
	}
}

// GetPendingReboot checks if a system reboot is pending
func (m *Manager) GetPendingReboot() bool {
	// Unix systems don't have a standard way to check for pending reboots
	return false
}

// Helper functions for system info

func getOSVersion() string {
	if runtime.GOOS == "linux" {
		// Try to read from /etc/os-release
		if data, err := os.ReadFile("/etc/os-release"); err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				if strings.HasPrefix(line, "PRETTY_NAME=") {
					version := strings.Trim(line[12:], `"`)
					return version
				}
			}
		}
	}
	return runtime.GOOS
}

func getKernelVersion() string {
	if runtime.GOOS == "linux" {
		if output, err := exec.Command("uname", "-r").Output(); err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return ""
}
