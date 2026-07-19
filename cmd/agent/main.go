package main

import (
	"fmt"
	"os"

	"github.com/CVE-Todo/CVETodo-agent/internal/agent"
	"github.com/CVE-Todo/CVETodo-agent/internal/config"
	"github.com/CVE-Todo/CVETodo-agent/internal/logger"
	svc "github.com/CVE-Todo/CVETodo-agent/internal/service"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "cvetodo-agent",
	Short: "CVETodo Agent - System vulnerability scanner",
	Long: `CVETodo Agent scans your system for installed software packages
and checks them against known CVE vulnerabilities using the CVETodo API.`,
	Version: fmt.Sprintf("%s (%s) built on %s", version, commit, date),
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Start the CVETodo agent",
	Long:  "Start the CVETodo agent to continuously monitor system for vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check if config file exists before attempting to load
		if !config.ConfigExists() {
			fmt.Fprintf(os.Stderr, "Configuration file not found at: %s\n", config.GetConfigPath())
			fmt.Fprintf(os.Stderr, "Please run 'cvetodo-agent config init' to set up your configuration.\n")
			return fmt.Errorf("configuration required")
		}

		// Load configuration
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		// Initialize logger
		log := logger.New(cfg.LogLevel, cfg.LogFormat)

		// Create and start agent
		agentInstance := agent.New(cfg, log)
		return agentInstance.Run()
	},
}

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Perform a one-time system scan",
	Long:  "Perform a one-time scan of the system and report vulnerabilities",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Check if config file exists before attempting to load
		if !config.ConfigExists() {
			fmt.Fprintf(os.Stderr, "Configuration file not found at: %s\n", config.GetConfigPath())
			fmt.Fprintf(os.Stderr, "Please run 'cvetodo-agent config init' to set up your configuration.\n")
			return fmt.Errorf("configuration required")
		}

		// Load configuration
		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("failed to load configuration: %w", err)
		}

		// Initialize logger
		log := logger.New(cfg.LogLevel, cfg.LogFormat)

		// Create and run scan
		agentInstance := agent.New(cfg, log)
		return agentInstance.Scan()
	},
}

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management",
	Long:  "Manage agent configuration",
}

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Manage the background service",
	Long: `Install and manage the CVETodo agent as a background service.

The service starts automatically on boot and scans the system once a day
by default (configurable via agent.scan_interval).

To stop scanning you can either:
  - run 'cvetodo-agent service stop' (or 'service uninstall')
  - set 'agent.enabled: false' in the configuration file
  - stop or disable the service in services.msc (Windows) or with
    'systemctl stop cvetodo-agent' / 'systemctl disable cvetodo-agent' (Linux)`,
}

var serviceInstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Install and start the background service",
	RunE: func(cmd *cobra.Command, args []string) error {
		if !config.ConfigExists() {
			fmt.Fprintf(os.Stderr, "Configuration file not found.\n")
			fmt.Fprintf(os.Stderr, "Please run 'cvetodo-agent config init' before installing the service.\n")
			return fmt.Errorf("configuration required")
		}

		if err := svc.Control("install"); err != nil {
			return err
		}
		fmt.Println("Service installed (starts automatically on boot).")

		if err := svc.Control("start"); err != nil {
			return err
		}
		fmt.Println("Service started. The system will be scanned once a day by default.")
		fmt.Println("To disable: 'cvetodo-agent service stop', set 'agent.enabled: false' in the config,")
		fmt.Println("or stop the 'CVETodo Agent' service in your system's service manager.")
		return nil
	},
}

var serviceUninstallCmd = &cobra.Command{
	Use:   "uninstall",
	Short: "Stop and remove the background service",
	RunE: func(cmd *cobra.Command, args []string) error {
		// Best effort stop; the service may not be running
		_ = svc.Control("stop")

		if err := svc.Control("uninstall"); err != nil {
			return err
		}
		fmt.Println("Service uninstalled.")
		return nil
	},
}

var serviceStartCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the background service",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := svc.Control("start"); err != nil {
			return err
		}
		fmt.Println("Service started.")
		return nil
	},
}

var serviceStopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the background service",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := svc.Control("stop"); err != nil {
			return err
		}
		fmt.Println("Service stopped. It will start again on next boot unless uninstalled or disabled.")
		return nil
	},
}

var serviceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show background service status",
	RunE: func(cmd *cobra.Command, args []string) error {
		status, err := svc.Status()
		if err != nil {
			return fmt.Errorf("failed to query service status (is the service installed?): %w", err)
		}
		fmt.Printf("Service status: %s\n", status)
		return nil
	},
}

// serviceRunCmd is the hidden entrypoint executed by the service manager
var serviceRunCmd = &cobra.Command{
	Use:    "run",
	Short:  "Run under the service manager (internal)",
	Hidden: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		s, err := svc.New()
		if err != nil {
			return err
		}
		return s.Run()
	},
}

var initConfigCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize configuration",
	Long:  "Create a default configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		force, _ := cmd.Flags().GetBool("force")
		return config.Init(force)
	},
}

var statusConfigCmd = &cobra.Command{
	Use:   "status",
	Short: "Check configuration status",
	Long:  "Check if configuration file exists and validate configuration",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := config.GetConfigPath()

		fmt.Printf("Configuration Status\n")
		fmt.Printf("===================\n\n")

		// Check if config file exists
		if config.ConfigExists() {
			fmt.Printf("✓ Config file exists: %s\n", configPath)

			// Try to load and validate configuration
			cfg, err := config.Load()
			if err != nil {
				fmt.Printf("✗ Configuration validation failed: %v\n", err)
				return nil
			}

			fmt.Printf("✓ Configuration is valid\n")
			fmt.Printf("  - API Base URL: %s\n", cfg.API.BaseURL)
			fmt.Printf("  - Team ID: %s\n", cfg.API.TeamID)
			fmt.Printf("  - API Key: %s (hidden)\n", maskString(cfg.API.APIKey))
			fmt.Printf("  - Agent Name: %s\n", cfg.Agent.Name)
			fmt.Printf("  - Scan Interval: %s\n", cfg.Agent.ScanInterval)
			fmt.Printf("  - Enabled Scanners: %v\n", cfg.Scanner.EnabledScanners)
		} else {
			fmt.Printf("✗ Config file not found: %s\n", configPath)
			fmt.Printf("\nTo create a configuration file, run:\n")
			fmt.Printf("  cvetodo-agent config init\n")
		}

		return nil
	},
}

// maskString masks all but the last 4 characters of a string
func maskString(s string) string {
	if len(s) <= 12 {
		return "****"
	}
	return "****" + s[len(s)-4:]
}

func init() {
	// Add subcommands
	rootCmd.AddCommand(runCmd, scanCmd, configCmd, serviceCmd)
	configCmd.AddCommand(initConfigCmd, statusConfigCmd)
	serviceCmd.AddCommand(serviceInstallCmd, serviceUninstallCmd, serviceStartCmd, serviceStopCmd, serviceStatusCmd, serviceRunCmd)

	// Command-specific flags
	initConfigCmd.Flags().Bool("force", false, "Force overwrite existing configuration file")

	// Global flags
	rootCmd.PersistentFlags().StringP("config", "c", "", "config file (default is $HOME/.cvetodo-agent.yaml)")
	rootCmd.PersistentFlags().StringP("log-level", "l", "info", "log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "text", "log format (text, json)")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
