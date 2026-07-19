//go:build windows
// +build windows

package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/CVE-Todo/CVETodo-agent/internal/api"
	"github.com/CVE-Todo/CVETodo-agent/internal/config"
	"github.com/CVE-Todo/CVETodo-agent/internal/logger"
	"golang.org/x/sys/windows/registry"
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
		"dpkg":    func() Scanner { return NewDpkgScanner(m.logger) },
		"rpm":     func() Scanner { return NewRpmScanner(m.logger) },
		"pip":     func() Scanner { return NewPipScanner(m.logger) },
		"npm":     func() Scanner { return NewNpmScanner(m.logger) },
		"windows": func() Scanner { return NewWindowsScanner(m.logger) },
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

	// Add Windows OS as a package if running on Windows
	if runtime.GOOS == "windows" {
		osVersion := getOSVersion()
		kernelVersion := getKernelVersion()

		windowsPackage := api.Package{
			Name:        osVersion,
			Version:     kernelVersion,
			Type:        "windows-os",
			Description: "Microsoft Corporation",
		}
		allPackages = append(allPackages, windowsPackage)

		m.logger.WithComponent("scanner").
			WithField("name", osVersion).
			WithField("version", kernelVersion).
			Info("added Windows OS package")
	}

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
	return getWindowsPendingReboot()
}

// WindowsScanner scans Windows programs using PowerShell
type WindowsScanner struct {
	logger *logger.Logger
}

// NewWindowsScanner creates a new windows scanner
func NewWindowsScanner(logger *logger.Logger) *WindowsScanner {
	return &WindowsScanner{logger: logger}
}

func (s *WindowsScanner) Name() string {
	return "windows"
}

func (s *WindowsScanner) IsAvailable() bool {
	// Windows scanner is always available on Windows
	return runtime.GOOS == "windows"
}

func (s *WindowsScanner) ScanPackages() ([]api.Package, error) {
	var packages []api.Package

	// Scan installed programs from Windows Registry
	registryPackages, err := s.scanFromRegistry()
	if err != nil {
		s.logger.WithComponent("scanner").WithError(err).Warn("failed to scan registry")
	} else {
		packages = append(packages, registryPackages...)
	}

	// Scan from WMI Win32_Product (slower but more comprehensive)
	wmiPackages, err := s.scanFromWMI()
	if err != nil {
		s.logger.WithComponent("scanner").WithError(err).Warn("failed to scan WMI")
	} else {
		packages = append(packages, wmiPackages...)
	}

	// Remove duplicates
	packages = s.removeDuplicates(packages)

	return packages, nil
}

// scanFromRegistry scans installed programs from Windows Registry
func (s *WindowsScanner) scanFromRegistry() ([]api.Package, error) {
	// PowerShell script to query installed programs from registry
	psScript := `
	$uninstallPaths = @(
		"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
		"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
		"HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
	)
	
	$programs = @()
	foreach ($path in $uninstallPaths) {
		try {
			Get-ItemProperty $path -ErrorAction SilentlyContinue | 
			Where-Object { $_.DisplayName -and !$_.SystemComponent -and !$_.ParentKeyName } |
			ForEach-Object {
				$programs += [PSCustomObject]@{
					Name = $_.DisplayName
					Version = if ($_.DisplayVersion) { $_.DisplayVersion } else { "Unknown" }
					Publisher = if ($_.Publisher) { $_.Publisher } else { "Unknown" }
				}
			}
		} catch {}
	}
	
	$programs | Sort-Object Name -Unique | ConvertTo-Json
	`

	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("powershell registry scan failed: %w", err)
	}

	return s.parseJSONOutput(string(output), "registry")
}

// scanFromWMI scans installed programs using WMI Win32_Product
func (s *WindowsScanner) scanFromWMI() ([]api.Package, error) {
	// PowerShell script to query WMI Win32_Product
	psScript := `
	try {
		Get-WmiObject -Class Win32_Product | 
		Where-Object { $_.Name } |
		ForEach-Object {
			[PSCustomObject]@{
				Name = $_.Name
				Version = if ($_.Version) { $_.Version } else { "Unknown" }
				Publisher = if ($_.Vendor) { $_.Vendor } else { "Unknown" }
			}
		} | ConvertTo-Json
	} catch {
		Write-Error "WMI query failed: $_"
		exit 1
	}
	`

	cmd := exec.Command("powershell", "-Command", psScript)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("powershell WMI scan failed: %w", err)
	}

	return s.parseJSONOutput(string(output), "wmi")
}

// parseJSONOutput parses PowerShell JSON output into packages
func (s *WindowsScanner) parseJSONOutput(jsonOutput, source string) ([]api.Package, error) {
	if strings.TrimSpace(jsonOutput) == "" {
		return []api.Package{}, nil
	}

	var programs []struct {
		Name      string `json:"Name"`
		Version   string `json:"Version"`
		Publisher string `json:"Publisher"`
	}

	// Handle both single object and array responses
	if strings.HasPrefix(strings.TrimSpace(jsonOutput), "[") {
		if err := json.Unmarshal([]byte(jsonOutput), &programs); err != nil {
			return nil, fmt.Errorf("failed to parse JSON array from %s: %w", source, err)
		}
	} else {
		var program struct {
			Name      string `json:"Name"`
			Version   string `json:"Version"`
			Publisher string `json:"Publisher"`
		}
		if err := json.Unmarshal([]byte(jsonOutput), &program); err != nil {
			return nil, fmt.Errorf("failed to parse JSON object from %s: %w", source, err)
		}
		programs = append(programs, program)
	}

	var packages []api.Package
	for _, prog := range programs {
		if prog.Name != "" {
			packages = append(packages, api.Package{
				Name:        prog.Name,
				Version:     prog.Version,
				Type:        "windows",
				Description: prog.Publisher,
			})
		}
	}

	return packages, nil
}

// removeDuplicates removes duplicate packages based on name and version
func (s *WindowsScanner) removeDuplicates(packages []api.Package) []api.Package {
	seen := make(map[string]bool)
	var unique []api.Package

	for _, pkg := range packages {
		key := fmt.Sprintf("%s:%s", pkg.Name, pkg.Version)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, pkg)
		}
	}

	return unique
}

// Helper functions for system info

// getWindowsPendingReboot checks if a reboot is pending on Windows
func getWindowsPendingReboot() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// Check multiple locations for pending reboot indicators
	checks := []func() bool{
		checkWindowsUpdateReboot,
		checkComponentBasedServicing,
		checkSessionManager,
		checkFileRename,
	}

	for _, check := range checks {
		if check() {
			return true
		}
	}

	return false
}

// checkWindowsUpdateReboot checks Windows Update reboot pending
func checkWindowsUpdateReboot() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`, registry.QUERY_VALUE)
	if err == nil {
		key.Close()
		return true // Key exists means reboot required
	}
	return false
}

// checkComponentBasedServicing checks CBS pending reboot
func checkComponentBasedServicing() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`, registry.QUERY_VALUE)
	if err == nil {
		key.Close()
		return true // Key exists means reboot required
	}
	return false
}

// checkSessionManager checks Session Manager pending file operations
func checkSessionManager() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	// Check for PendingFileRenameOperations
	_, _, err = key.GetStringsValue("PendingFileRenameOperations")
	return err == nil
}

// checkFileRename checks for pending file rename operations
func checkFileRename() bool {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer key.Close()

	// Check for PendingFileRenameOperations2
	_, _, err = key.GetStringsValue("PendingFileRenameOperations2")
	return err == nil
}

func getOSVersion() string {
	if runtime.GOOS == "windows" {
		// Get Windows version information using Windows registry
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
		if err != nil {
			return "Windows"
		}
		defer key.Close()

		// Get product name
		productName, _, err := key.GetStringValue("ProductName")
		if err != nil {
			productName = "Windows"
		}

		// Try to get display version (Windows 10 20H2+)
		displayVersion, _, err := key.GetStringValue("DisplayVersion")
		if err == nil && displayVersion != "" {
			return fmt.Sprintf("%s %s", productName, displayVersion)
		}

		// Fallback to ReleaseId for older Windows 10 versions
		releaseId, _, err := key.GetStringValue("ReleaseId")
		if err == nil && releaseId != "" {
			return fmt.Sprintf("%s %s", productName, releaseId)
		}

		return productName
	} else if runtime.GOOS == "linux" {
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
	if runtime.GOOS == "windows" {
		// Get Windows build number using Windows registry
		key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
		if err != nil {
			return ""
		}
		defer key.Close()

		// Get current build number
		currentBuild, _, err := key.GetStringValue("CurrentBuild")
		if err != nil {
			return ""
		}

		// Get UBR (Update Build Revision) if available
		ubr, _, err := key.GetIntegerValue("UBR")
		if err == nil {
			return fmt.Sprintf("%s.%d", currentBuild, ubr)
		}

		return currentBuild
	} else if runtime.GOOS == "linux" {
		if output, err := exec.Command("uname", "-r").Output(); err == nil {
			return strings.TrimSpace(string(output))
		}
	}
	return ""
}
