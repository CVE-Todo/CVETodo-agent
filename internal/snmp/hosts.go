// Package snmp polls network devices over SNMP for inventory reporting.
//
// Device targets and credentials live in a hosts file (default
// ~/cvetodo_snmp_hosts.txt), one entry per line:
//
//	<host> key=value ...
//
// Blank lines and lines starting with # are ignored. Values may be double
// quoted to contain spaces. Keys:
//
//	common: port=161  name=<label & stable identity override>
//	v2c:    community=<string>                          (implies SNMP v2c)
//	v3:     user=<string>                               (implies SNMP v3)
//	        level=noAuthNoPriv|authNoPriv|authPriv
//	        auth=MD5|SHA|SHA224|SHA256|SHA384|SHA512    authpass=<string>
//	        priv=DES|AES|AES192|AES256|AES192C|AES256C  privpass=<string>
//
// When level is omitted it is derived: privpass set -> authPriv, authpass
// set -> authNoPriv, otherwise noAuthNoPriv. Note "SHA" means SHA-1; use
// SHA256 etc. for SHA-2. gosnmp's AES256 is the Blumenthal draft variant --
// most network gear (Cisco et al.) implements the Reeder variant AES256C.
package snmp

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

// HostEntry is one parsed line of the hosts file
type HostEntry struct {
	Host      string
	Port      uint16
	Name      string // optional label + identity override
	Version   gosnmp.SnmpVersion
	Community string    // v2c
	V3        *V3Params // v3
}

// V3Params holds SNMPv3 USM security parameters
type V3Params struct {
	User     string
	AuthPass string
	PrivPass string
	Level    gosnmp.SnmpV3MsgFlags
	Auth     gosnmp.SnmpV3AuthProtocol
	Priv     gosnmp.SnmpV3PrivProtocol
}

var authProtocols = map[string]gosnmp.SnmpV3AuthProtocol{
	"MD5":    gosnmp.MD5,
	"SHA":    gosnmp.SHA,
	"SHA224": gosnmp.SHA224,
	"SHA256": gosnmp.SHA256,
	"SHA384": gosnmp.SHA384,
	"SHA512": gosnmp.SHA512,
}

var privProtocols = map[string]gosnmp.SnmpV3PrivProtocol{
	"DES":     gosnmp.DES,
	"AES":     gosnmp.AES,
	"AES192":  gosnmp.AES192,
	"AES256":  gosnmp.AES256,
	"AES192C": gosnmp.AES192C,
	"AES256C": gosnmp.AES256C,
}

var securityLevels = map[string]gosnmp.SnmpV3MsgFlags{
	"NOAUTHNOPRIV": gosnmp.NoAuthNoPriv,
	"AUTHNOPRIV":   gosnmp.AuthNoPriv,
	"AUTHPRIV":     gosnmp.AuthPriv,
}

// ParseHostsFile reads and parses the SNMP hosts file. It refuses files
// readable by group/other (they contain credentials).
func ParseHostsFile(path string, defaultPort uint16) ([]HostEntry, error) {
	if err := checkHostsFilePerms(path); err != nil {
		return nil, err
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()

	var entries []HostEntry
	seen := make(map[string]int) // identity -> line number
	scanner := bufio.NewScanner(file)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		entry, err := parseLine(line, lineNo, defaultPort)
		if err != nil {
			return nil, err
		}

		id := DiscoveryKey(*entry)
		if prev, dup := seen[id]; dup {
			return nil, fmt.Errorf("%s line %d: duplicate device identity %q (first seen on line %d); use name= to distinguish", path, lineNo, id, prev)
		}
		seen[id] = lineNo

		entries = append(entries, *entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	return entries, nil
}

// DiscoveryKey returns the stable identity for a device: the name= override
// when set, else the lowercased host plus the port when non-standard. sysName
// is deliberately not used -- it is mutable and collides across devices.
func DiscoveryKey(e HostEntry) string {
	if e.Name != "" {
		return e.Name
	}
	key := "snmp:" + strings.ToLower(e.Host)
	if e.Port != 161 {
		key += ":" + strconv.Itoa(int(e.Port))
	}
	return key
}

// parseLine parses one hosts-file entry
func parseLine(line string, lineNo int, defaultPort uint16) (*HostEntry, error) {
	fields, err := splitFields(line)
	if err != nil {
		return nil, fmt.Errorf("line %d: %w", lineNo, err)
	}
	return ParseEntryFields(fields, lineNo, defaultPort)
}

// ParseEntryFields parses an already-tokenized hosts entry
// (host followed by key=value fields). Used by the hosts-file parser and the
// `snmp test` command, whose shell has already split the tokens.
func ParseEntryFields(fields []string, lineNo int, defaultPort uint16) (*HostEntry, error) {
	if len(fields) == 0 {
		return nil, fmt.Errorf("line %d: empty entry", lineNo)
	}

	entry := &HostEntry{
		Host: fields[0],
		Port: defaultPort,
	}
	if strings.Contains(entry.Host, "=") {
		return nil, fmt.Errorf("line %d: first token must be a host address, got %q", lineNo, entry.Host)
	}

	var (
		community, user, level string
		authProto, privProto   string
		authPass, privPass     string
	)

	for _, field := range fields[1:] {
		key, value, ok := strings.Cut(field, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key=value, got %q", lineNo, field)
		}
		switch strings.ToLower(key) {
		case "port":
			p, err := strconv.ParseUint(value, 10, 16)
			if err != nil || p == 0 {
				return nil, fmt.Errorf("line %d: invalid port %q", lineNo, value)
			}
			entry.Port = uint16(p)
		case "name":
			entry.Name = value
		case "community":
			community = value
		case "user":
			user = value
		case "level":
			level = value
		case "auth":
			authProto = value
		case "authpass":
			authPass = value
		case "priv":
			privProto = value
		case "privpass":
			privPass = value
		default:
			return nil, fmt.Errorf("line %d: unknown key %q", lineNo, key)
		}
	}

	switch {
	case community != "" && user != "":
		return nil, fmt.Errorf("line %d: community= (v2c) and user= (v3) are mutually exclusive", lineNo)
	case community != "":
		entry.Version = gosnmp.Version2c
		entry.Community = community
	case user != "":
		entry.Version = gosnmp.Version3
		v3, err := buildV3Params(lineNo, user, level, authProto, authPass, privProto, privPass)
		if err != nil {
			return nil, err
		}
		entry.V3 = v3
	default:
		return nil, fmt.Errorf("line %d: need community= (v2c) or user= (v3)", lineNo)
	}

	return entry, nil
}

// buildV3Params validates and assembles SNMPv3 security parameters
func buildV3Params(lineNo int, user, level, authProto, authPass, privProto, privPass string) (*V3Params, error) {
	v3 := &V3Params{User: user, AuthPass: authPass, PrivPass: privPass}

	if level == "" {
		// Derive from supplied credentials
		switch {
		case privPass != "":
			v3.Level = gosnmp.AuthPriv
		case authPass != "":
			v3.Level = gosnmp.AuthNoPriv
		default:
			v3.Level = gosnmp.NoAuthNoPriv
		}
	} else {
		l, ok := securityLevels[strings.ToUpper(level)]
		if !ok {
			return nil, fmt.Errorf("line %d: invalid level %q (want noAuthNoPriv, authNoPriv or authPriv)", lineNo, level)
		}
		v3.Level = l
	}

	if v3.Level != gosnmp.NoAuthNoPriv {
		if authPass == "" {
			return nil, fmt.Errorf("line %d: level %s requires authpass=", lineNo, levelName(v3.Level))
		}
		proto := strings.ToUpper(authProto)
		if proto == "" {
			proto = "SHA"
		}
		p, ok := authProtocols[proto]
		if !ok {
			return nil, fmt.Errorf("line %d: invalid auth protocol %q (want MD5, SHA, SHA224, SHA256, SHA384 or SHA512; SHA means SHA-1)", lineNo, authProto)
		}
		v3.Auth = p
	}

	if v3.Level == gosnmp.AuthPriv {
		if privPass == "" {
			return nil, fmt.Errorf("line %d: level authPriv requires privpass=", lineNo)
		}
		proto := strings.ToUpper(privProto)
		if proto == "" {
			proto = "AES"
		}
		p, ok := privProtocols[proto]
		if !ok {
			return nil, fmt.Errorf("line %d: invalid priv protocol %q (want DES, AES, AES192, AES256, AES192C or AES256C; Cisco-style AES-256 is AES256C)", lineNo, privProto)
		}
		v3.Priv = p
	}

	return v3, nil
}

func levelName(l gosnmp.SnmpV3MsgFlags) string {
	switch l {
	case gosnmp.AuthPriv:
		return "authPriv"
	case gosnmp.AuthNoPriv:
		return "authNoPriv"
	default:
		return "noAuthNoPriv"
	}
}

// splitFields splits a line on whitespace, honoring double-quoted segments
// (community=\"my secret\" or authpass=\"a b c\")
func splitFields(line string) ([]string, error) {
	var fields []string
	var current strings.Builder
	inQuote := false

	for _, r := range line {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			if current.Len() > 0 {
				fields = append(fields, current.String())
				current.Reset()
			}
		default:
			current.WriteRune(r)
		}
	}
	if inQuote {
		return nil, fmt.Errorf("unterminated quote")
	}
	if current.Len() > 0 {
		fields = append(fields, current.String())
	}
	if len(fields) == 0 {
		return nil, fmt.Errorf("empty entry")
	}
	return fields, nil
}
