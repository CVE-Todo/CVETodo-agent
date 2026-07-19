package scanner

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/CVE-Todo/CVETodo-agent/internal/api"
	"github.com/CVE-Todo/CVETodo-agent/internal/logger"
)

// DpkgScanner scans Debian/Ubuntu packages
type DpkgScanner struct {
	logger *logger.Logger
}

// NewDpkgScanner creates a new dpkg scanner
func NewDpkgScanner(logger *logger.Logger) *DpkgScanner {
	return &DpkgScanner{logger: logger}
}

func (s *DpkgScanner) Name() string {
	return "dpkg"
}

func (s *DpkgScanner) IsAvailable() bool {
	_, err := exec.LookPath("dpkg-query")
	return err == nil
}

func (s *DpkgScanner) ScanPackages() ([]api.Package, error) {
	cmd := exec.Command("dpkg-query", "-W", "-f", `{"name":"${Package}","version":"${Version}","description":"${Description}"}\n`)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("dpkg scan failed: %w", err)
	}

	var packages []api.Package
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		var pkg struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			Description string `json:"description"`
		}

		if err := json.Unmarshal([]byte(line), &pkg); err != nil {
			s.logger.WithComponent("scanner").WithError(err).Warn("failed to parse dpkg package")
			continue
		}

		packages = append(packages, api.Package{
			Name:        pkg.Name,
			Version:     pkg.Version,
			Type:        "dpkg",
			Description: pkg.Description,
		})
	}

	return packages, nil
}

// RpmScanner scans RPM packages
type RpmScanner struct {
	logger *logger.Logger
}

// NewRpmScanner creates a new rpm scanner
func NewRpmScanner(logger *logger.Logger) *RpmScanner {
	return &RpmScanner{logger: logger}
}

func (s *RpmScanner) Name() string {
	return "rpm"
}

func (s *RpmScanner) IsAvailable() bool {
	_, err := exec.LookPath("rpm")
	return err == nil
}

func (s *RpmScanner) ScanPackages() ([]api.Package, error) {
	cmd := exec.Command("rpm", "-qa", "--queryformat", `{"name":"%{NAME}","version":"%{VERSION}-%{RELEASE}","description":"%{SUMMARY}"}\n`)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("rpm scan failed: %w", err)
	}

	var packages []api.Package
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		var pkg struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			Description string `json:"description"`
		}

		if err := json.Unmarshal([]byte(line), &pkg); err != nil {
			s.logger.WithComponent("scanner").WithError(err).Warn("failed to parse rpm package")
			continue
		}

		packages = append(packages, api.Package{
			Name:        pkg.Name,
			Version:     pkg.Version,
			Type:        "rpm",
			Description: pkg.Description,
		})
	}

	return packages, nil
}

// PipScanner scans Python packages
type PipScanner struct {
	logger *logger.Logger
}

// NewPipScanner creates a new pip scanner
func NewPipScanner(logger *logger.Logger) *PipScanner {
	return &PipScanner{logger: logger}
}

func (s *PipScanner) Name() string {
	return "pip"
}

func (s *PipScanner) IsAvailable() bool {
	_, err := exec.LookPath("pip3")
	return err == nil
}

func (s *PipScanner) ScanPackages() ([]api.Package, error) {
	cmd := exec.Command("pip3", "list", "--format=json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("pip scan failed: %w", err)
	}

	var pipPackages []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}

	if err := json.Unmarshal(output, &pipPackages); err != nil {
		return nil, fmt.Errorf("failed to parse pip packages: %w", err)
	}

	var packages []api.Package
	for _, pkg := range pipPackages {
		packages = append(packages, api.Package{
			Name:        pkg.Name,
			Version:     pkg.Version,
			Type:        "pip",
			Description: "Python package",
		})
	}

	return packages, nil
}

// NpmScanner scans Node.js packages
type NpmScanner struct {
	logger *logger.Logger
}

// NewNpmScanner creates a new npm scanner
func NewNpmScanner(logger *logger.Logger) *NpmScanner {
	return &NpmScanner{logger: logger}
}

func (s *NpmScanner) Name() string {
	return "npm"
}

func (s *NpmScanner) IsAvailable() bool {
	_, err := exec.LookPath("npm")
	return err == nil
}

func (s *NpmScanner) ScanPackages() ([]api.Package, error) {
	cmd := exec.Command("npm", "list", "-g", "--json")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("npm scan failed: %w", err)
	}

	var npmPackages map[string]struct {
		Version     string `json:"version"`
		Description string `json:"description"`
	}

	if err := json.Unmarshal(output, &npmPackages); err != nil {
		return nil, fmt.Errorf("failed to parse npm packages: %w", err)
	}

	var packages []api.Package
	for name, pkg := range npmPackages {
		packages = append(packages, api.Package{
			Name:        name,
			Version:     pkg.Version,
			Type:        "npm",
			Description: pkg.Description,
		})
	}

	return packages, nil
}
