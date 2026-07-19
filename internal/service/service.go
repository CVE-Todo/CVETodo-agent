package service

import (
	"fmt"

	"github.com/kardianos/service"

	"github.com/aecwalker/CVETodo-agent/internal/agent"
	"github.com/aecwalker/CVETodo-agent/internal/config"
	"github.com/aecwalker/CVETodo-agent/internal/logger"
)

// Name is the system service name used across platforms
const Name = "cvetodo-agent"

// program implements service.Interface. Configuration is loaded in Start
// rather than at construction time because the service manager runs the
// agent under a different account (LocalSystem/root) than the one that
// installed it.
type program struct {
	agent *agent.Agent
}

// Start is called by the service manager; it must not block.
func (p *program) Start(s service.Service) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	log := logger.New(cfg.LogLevel, cfg.LogFormat)
	p.agent = agent.New(cfg, log)

	go func() {
		if err := p.agent.Run(); err != nil {
			log.WithComponent("service").WithError(err).Error("agent stopped with error")
		}
	}()

	return nil
}

// Stop is called by the service manager to shut the agent down.
func (p *program) Stop(s service.Service) error {
	if p.agent != nil {
		p.agent.Stop()
	}
	return nil
}

// New creates the system service definition for the agent.
func New() (service.Service, error) {
	svcConfig := &service.Config{
		Name:        Name,
		DisplayName: "CVETodo Agent",
		Description: "Scans installed software daily and reports it to CVETodo for CVE monitoring.",
		Arguments:   []string{"service", "run"},
	}

	return service.New(&program{}, svcConfig)
}

// Control runs a service control action (install, uninstall, start, stop)
// with a friendlier error for missing privileges.
func Control(action string) error {
	svc, err := New()
	if err != nil {
		return fmt.Errorf("failed to create service definition: %w", err)
	}

	if err := service.Control(svc, action); err != nil {
		return fmt.Errorf("failed to %s service (administrator/root privileges are required): %w", action, err)
	}

	return nil
}

// Status returns a human-readable status of the installed service.
func Status() (string, error) {
	svc, err := New()
	if err != nil {
		return "", fmt.Errorf("failed to create service definition: %w", err)
	}

	status, err := svc.Status()
	if err != nil {
		return "", err
	}

	switch status {
	case service.StatusRunning:
		return "running", nil
	case service.StatusStopped:
		return "stopped", nil
	default:
		return "unknown", nil
	}
}
