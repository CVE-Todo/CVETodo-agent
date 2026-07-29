package snmp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"

	"github.com/CVE-Todo/CVETodo-agent/internal/api"
	"github.com/CVE-Todo/CVETodo-agent/internal/config"
	"github.com/CVE-Todo/CVETodo-agent/internal/logger"
)

// Poller polls SNMP devices listed in the hosts file
type Poller struct {
	cfg    *config.Config
	logger *logger.Logger
}

// New creates a new SNMP poller
func New(cfg *config.Config, log *logger.Logger) *Poller {
	return &Poller{cfg: cfg, logger: log}
}

// Poll reads the hosts file (fresh each call, so edits are picked up without
// a restart) and polls every device. Per-device failures are logged and the
// device is omitted from the result — its last_seen_at then goes stale
// server-side rather than being falsely refreshed.
func (p *Poller) Poll(ctx context.Context) ([]api.Device, error) {
	entries, err := ParseHostsFile(p.cfg.SNMP.HostsFile, p.cfg.SNMP.Port)
	if err != nil {
		return nil, fmt.Errorf("snmp hosts file: %w", err)
	}
	if len(entries) == 0 {
		p.logger.WithComponent("snmp").Info("snmp hosts file has no devices")
		return nil, nil
	}

	maxConcurrent := p.cfg.SNMP.MaxConcurrent
	if maxConcurrent < 1 {
		maxConcurrent = 1
	}
	sem := make(chan struct{}, maxConcurrent)

	var (
		mu      sync.Mutex
		devices []api.Device
		wg      sync.WaitGroup
	)

	for _, entry := range entries {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		go func(e HostEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			device, err := p.pollDevice(ctx, e)
			if err != nil {
				p.logger.WithComponent("snmp").
					WithField("host", e.Host).
					WithError(err).
					Warn("device poll failed")
				return
			}

			mu.Lock()
			devices = append(devices, *device)
			mu.Unlock()
		}(entry)
	}
	wg.Wait()

	p.logger.WithComponent("snmp").
		WithField("configured", len(entries)).
		WithField("responded", len(devices)).
		Info("snmp poll completed")

	return devices, ctx.Err()
}

// PollOne polls a single host entry; used by the `snmp test` command
func (p *Poller) PollOne(ctx context.Context, entry HostEntry) (*api.Device, error) {
	return p.pollDevice(ctx, entry)
}

// pollDevice connects to one device and builds its inventory record
func (p *Poller) pollDevice(ctx context.Context, entry HostEntry) (*api.Device, error) {
	conn, err := p.connect(ctx, entry)
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Conn.Close() }()

	// System group: sysDescr, sysObjectID, sysName
	result, err := conn.Get([]string{oidSysDescr, oidSysObjectID, oidSysName})
	if err != nil {
		return nil, fmt.Errorf("system group get: %w", err)
	}

	var sysDescr, sysObjectID, sysName string
	for _, v := range result.Variables {
		switch v.Name {
		case oidSysDescr:
			sysDescr = pduString(v)
		case oidSysObjectID:
			sysObjectID = pduString(v)
		case oidSysName:
			sysName = pduString(v)
		}
	}
	sysDescr = truncateRunes(strings.TrimSpace(sysDescr), maxSysDescrRunes)

	device := &api.Device{
		DiscoveryKey: DiscoveryKey(entry),
		Address:      entry.Host,
		Name:         entry.Name,
		SysName:      strings.TrimSpace(sysName),
		SysDescr:     sysDescr,
		SysObjectID:  sysObjectID,
		Version:      unknownVersion,
	}

	var profile *vendorProfile
	if prof, ok := profileFor(sysObjectID); ok {
		profile = &prof
		device.VendorGuess = prof.Vendor
		device.ProductGuess = prof.Product
		device.CategoryGuess = prof.Category
		if prof.RefineProduct != nil {
			if refined := prof.RefineProduct(sysDescr); refined != "" {
				device.ProductGuess = refined
			}
		}
	} else {
		device.CategoryGuess = "other"
	}

	if version := p.resolveVersion(conn, profile, sysDescr); version != "" {
		device.Version = version
	}

	return device, nil
}

// resolveVersion tries, in order: vendor version OIDs, vendor sysDescr regex,
// ENTITY-MIB entPhysicalSoftwareRev, generic sysDescr regexes.
func (p *Poller) resolveVersion(conn *gosnmp.GoSNMP, profile *vendorProfile, sysDescr string) string {
	if profile != nil {
		for _, oid := range profile.VersionOIDs {
			result, err := conn.Get([]string{oid})
			if err != nil || len(result.Variables) == 0 {
				continue
			}
			if v := cleanVersion(pduString(result.Variables[0])); v != "" {
				return v
			}
		}
		if profile.DescrRegex != nil {
			if v := versionFromDescr(profile, sysDescr); v != "" {
				return v
			}
		}
	}

	if v := p.entityMibVersion(conn); v != "" {
		return v
	}

	return versionFromDescr(nil, sysDescr)
}

// entityMibVersion walks entPhysicalSoftwareRev and returns the first
// non-empty revision (usually the chassis row)
func (p *Poller) entityMibVersion(conn *gosnmp.GoSNMP) string {
	var version string
	err := conn.BulkWalk(oidEntPhysicalSoftwareRev, func(pdu gosnmp.SnmpPDU) error {
		if v := cleanVersion(pduString(pdu)); v != "" {
			version = v
			return fmt.Errorf("done") // stop the walk
		}
		return nil
	})
	_ = err // walk errors (including our sentinel) are fine; version rules
	return version
}

// connect builds and opens a gosnmp connection for a host entry
func (p *Poller) connect(ctx context.Context, entry HostEntry) (*gosnmp.GoSNMP, error) {
	timeout, err := time.ParseDuration(p.cfg.SNMP.Timeout)
	if err != nil || timeout <= 0 {
		timeout = 5 * time.Second
	}
	retries := p.cfg.SNMP.Retries
	if retries < 0 {
		retries = 0
	}

	conn := &gosnmp.GoSNMP{
		Target:  entry.Host,
		Port:    entry.Port,
		Version: entry.Version,
		Timeout: timeout,
		Retries: retries,
		Context: ctx,
	}

	switch entry.Version {
	case gosnmp.Version3:
		conn.SecurityModel = gosnmp.UserSecurityModel
		conn.MsgFlags = entry.V3.Level
		conn.SecurityParameters = &gosnmp.UsmSecurityParameters{
			UserName:                 entry.V3.User,
			AuthenticationProtocol:   entry.V3.Auth,
			AuthenticationPassphrase: entry.V3.AuthPass,
			PrivacyProtocol:          entry.V3.Priv,
			PrivacyPassphrase:        entry.V3.PrivPass,
		}
	default:
		conn.Community = entry.Community
	}

	if err := conn.Connect(); err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	return conn, nil
}

// pduString renders an SNMP PDU value as a string
func pduString(pdu gosnmp.SnmpPDU) string {
	switch v := pdu.Value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}
