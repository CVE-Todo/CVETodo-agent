package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configuration for the agent
type Config struct {
	// CVETodo API configuration
	API APIConfig `mapstructure:"api"`

	// Agent configuration
	Agent AgentConfig `mapstructure:"agent"`

	// Logging configuration
	LogLevel  string `mapstructure:"log_level"`
	LogFormat string `mapstructure:"log_format"`

	// Scanner configuration
	Scanner ScannerConfig `mapstructure:"scanner"`
}

// APIConfig holds CVETodo API settings
type APIConfig struct {
	BaseURL string `mapstructure:"base_url"`
	APIKey  string `mapstructure:"api_key"`
	TeamID  string `mapstructure:"team_id"`
	Timeout string `mapstructure:"timeout"`
}

// AgentConfig holds agent runtime settings
type AgentConfig struct {
	Enabled        bool          `mapstructure:"enabled"`
	Name           string        `mapstructure:"name"`
	ScanInterval   time.Duration `mapstructure:"scan_interval"`
	ReportInterval time.Duration `mapstructure:"report_interval"`
	DataDir        string        `mapstructure:"data_dir"`
}

// ScannerConfig holds package scanning settings
type ScannerConfig struct {
	EnabledScanners []string          `mapstructure:"enabled_scanners"`
	ScannerSettings map[string]string `mapstructure:"scanner_settings"`
}

// Load loads configuration from file and environment variables
func Load() (*Config, error) {
	v := viper.New()

	// Set defaults
	setDefaults(v)

	// Configuration file settings
	v.SetConfigName(".cvetodo-agent")
	v.SetConfigType("yaml")
	for _, path := range getSearchPaths() {
		v.AddConfigPath(path)
	}

	// Environment variables
	v.SetEnvPrefix("CVETODO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Read config file
	configFileFound := true
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			configFileFound = false
		} else {
			return nil, fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Unmarshal config
	var config Config
	if err := v.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("error unmarshaling config: %w", err)
	}

	// If no config file was found and API key is missing, suggest running config init
	if !configFileFound && config.API.APIKey == "" {
		configPath := filepath.Join(getHomeDir(), ".cvetodo-agent.yaml")
		return nil, fmt.Errorf("no configuration file found at %s. Please run 'cvetodo-agent config init' to set up your configuration", configPath)
	}

	// Validate required fields
	if err := validate(&config); err != nil {
		return nil, fmt.Errorf("configuration validation failed: %w", err)
	}

	return &config, nil
}

// setDefaults sets default configuration values
func setDefaults(v *viper.Viper) {
	// API defaults - point to the production CVETodo API
	v.SetDefault("api.base_url", "https://cvetodo.com")
	v.SetDefault("api.timeout", "30s")

	// Agent defaults
	v.SetDefault("agent.enabled", true)
	v.SetDefault("agent.name", getHostname())
	v.SetDefault("agent.scan_interval", "24h")
	v.SetDefault("agent.report_interval", "24h")
	v.SetDefault("agent.data_dir", getDefaultDataDir())

	// Logging defaults
	v.SetDefault("log_level", "info")
	v.SetDefault("log_format", "text")

	// Scanner defaults - include Windows scanner
	v.SetDefault("scanner.enabled_scanners", []string{"dpkg", "rpm", "pip", "npm", "windows"})
}

// validate validates the configuration
func validate(config *Config) error {
	configPath := filepath.Join(getHomeDir(), ".cvetodo-agent.yaml")

	if config.API.APIKey == "" {
		return fmt.Errorf("api.api_key is required. Please run 'cvetodo-agent config init' to set up your configuration, or check that your config file exists at: %s", configPath)
	}

	if config.API.TeamID == "" {
		return fmt.Errorf("api.team_id is required. Please run 'cvetodo-agent config init' to set up your configuration, or check that your config file exists at: %s", configPath)
	}

	if config.API.BaseURL == "" {
		return fmt.Errorf("api.base_url is required")
	}

	return nil
}

// Init creates a default configuration file
func Init(force bool) error {
	configPath := filepath.Join(getHomeDir(), ".cvetodo-agent.yaml")

	// Check if config file already exists
	if _, err := os.Stat(configPath); err == nil {
		if !force {
			// Config file exists, ask user if they want to replace it
			scanner := bufio.NewScanner(os.Stdin)

			fmt.Printf("Configuration file already exists at: %s\n", configPath)
			fmt.Print("Do you want to replace it? (y/N): ")

			scanner.Scan()
			response := strings.ToLower(strings.TrimSpace(scanner.Text()))

			if response != "y" && response != "yes" {
				fmt.Println("Configuration initialization cancelled.")
				return nil
			}
		}

		fmt.Println("Replacing existing configuration...")
	}

	// Prompt user for configuration values
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println("CVETodo Agent Configuration Setup")
	fmt.Println("=================================")
	fmt.Println()
	fmt.Println("To obtain your API key and team ID:")
	fmt.Println("1. Log into your CVETodo account")
	fmt.Println("2. Navigate to your team settings")
	fmt.Println("3. Go to the 'Agent Keys' section")
	fmt.Println("4. Generate a new API key for this agent")
	fmt.Println()

	// Prompt for API key
	fmt.Print("Enter your CVETodo team API key: ")
	scanner.Scan()
	apiKey := strings.TrimSpace(scanner.Text())
	if apiKey == "" {
		return fmt.Errorf("API key is required")
	}

	// Prompt for team ID
	fmt.Print("Enter your CVETodo team ID: ")
	scanner.Scan()
	teamID := strings.TrimSpace(scanner.Text())
	if teamID == "" {
		return fmt.Errorf("team ID is required")
	}

	// Check for scanner errors
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading input: %w", err)
	}

	// Create default config content with actual values
	defaultConfig := fmt.Sprintf(`# CVETodo Agent Configuration
api:
  base_url: "https://cvetodo.com"
  api_key: "%s"
  team_id: "%s"
  timeout: "30s"

agent:
  enabled: true       # set to false to disable all scanning without uninstalling
  name: "%s"
  scan_interval: "24h"
  report_interval: "24h"
  data_dir: "%s"

log_level: "info"
log_format: "text"

scanner:
  enabled_scanners:
    - "dpkg"      # Debian/Ubuntu packages
    - "rpm"       # RedHat/CentOS/SUSE packages  
    - "pip"       # Python packages
    - "npm"       # Node.js packages
    - "windows"   # Windows packages
  scanner_settings:
    # Additional scanner-specific settings can be added here
`, apiKey, teamID, getHostname(), getDefaultDataDir())

	// Write config file
	if err := os.WriteFile(configPath, []byte(defaultConfig), 0600); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	fmt.Printf("\nConfiguration file created at: %s\n", configPath)
	fmt.Println("You can now run 'cvetodo-agent scan' to perform your first vulnerability scan.")

	return nil
}

// getSearchPaths returns the directories searched for the configuration
// file, in priority order. Machine-wide locations are included so the
// agent finds its configuration when running as a system service under
// a different account (LocalSystem/root) than the one that installed it.
func getSearchPaths() []string {
	paths := []string{".", getHomeDir()}

	if runtime.GOOS == "windows" {
		if programData := os.Getenv("PROGRAMDATA"); programData != "" {
			paths = append(paths, filepath.Join(programData, "cvetodo-agent"))
		}
	} else {
		paths = append(paths, "/etc/cvetodo-agent")
	}

	return paths
}

// getHostname returns the system hostname
func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

// getHomeDir returns the user's home directory
func getHomeDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "."
	}
	return home
}

// getDefaultDataDir returns the default data directory
func getDefaultDataDir() string {
	home := getHomeDir()
	// Use forward slashes for YAML compatibility on all platforms
	dataDir := filepath.Join(home, ".cvetodo-agent", "data")
	// Convert Windows backslashes to forward slashes for YAML
	return strings.ReplaceAll(dataDir, "\\", "/")
}

// ConfigExists checks if the configuration file exists in any search path
func ConfigExists() bool {
	for _, dir := range getSearchPaths() {
		if _, err := os.Stat(filepath.Join(dir, ".cvetodo-agent.yaml")); err == nil {
			return true
		}
	}
	return false
}

// GetConfigPath returns the expected configuration file path
func GetConfigPath() string {
	return filepath.Join(getHomeDir(), ".cvetodo-agent.yaml")
}
