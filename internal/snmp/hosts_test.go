package snmp

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gosnmp/gosnmp"
)

func writeHostsFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseHostsFileV2c(t *testing.T) {
	path := writeHostsFile(t, `
# edge firewalls
10.0.0.1  community=public  name=edge-fw-akl
core-sw1.corp community=ro-string port=1161
`, 0600)

	entries, err := ParseHostsFile(path, 161)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(entries))
	}

	e := entries[0]
	if e.Host != "10.0.0.1" || e.Community != "public" || e.Name != "edge-fw-akl" || e.Port != 161 {
		t.Errorf("entry 0 parsed wrong: %+v", e)
	}
	if e.Version != gosnmp.Version2c {
		t.Errorf("entry 0: want v2c, got %v", e.Version)
	}
	if DiscoveryKey(e) != "edge-fw-akl" {
		t.Errorf("name= should be identity, got %q", DiscoveryKey(e))
	}

	e = entries[1]
	if e.Host != "core-sw1.corp" || e.Port != 1161 {
		t.Errorf("entry 1 parsed wrong: %+v", e)
	}
	if DiscoveryKey(e) != "snmp:core-sw1.corp:1161" {
		t.Errorf("non-default port must be part of identity, got %q", DiscoveryKey(e))
	}
}

func TestParseHostsFileV3(t *testing.T) {
	path := writeHostsFile(t,
		`10.0.0.2 user=cvetodo auth=SHA256 authpass="s3cret pass" priv=AES256C privpass=abc level=authPriv`, 0600)

	entries, err := ParseHostsFile(path, 161)
	if err != nil {
		t.Fatal(err)
	}
	e := entries[0]
	if e.Version != gosnmp.Version3 || e.V3 == nil {
		t.Fatalf("want v3 entry, got %+v", e)
	}
	if e.V3.User != "cvetodo" || e.V3.AuthPass != "s3cret pass" || e.V3.PrivPass != "abc" {
		t.Errorf("v3 credentials parsed wrong: %+v", e.V3)
	}
	if e.V3.Auth != gosnmp.SHA256 || e.V3.Priv != gosnmp.AES256C || e.V3.Level != gosnmp.AuthPriv {
		t.Errorf("v3 protocols parsed wrong: %+v", e.V3)
	}
}

func TestV3LevelDerivation(t *testing.T) {
	cases := []struct {
		line string
		want gosnmp.SnmpV3MsgFlags
	}{
		{"h user=u", gosnmp.NoAuthNoPriv},
		{"h user=u authpass=a", gosnmp.AuthNoPriv},
		{"h user=u authpass=a privpass=p", gosnmp.AuthPriv},
	}
	for _, c := range cases {
		entry, err := parseLine(c.line, 1, 161)
		if err != nil {
			t.Fatalf("%q: %v", c.line, err)
		}
		if entry.V3.Level != c.want {
			t.Errorf("%q: want level %v, got %v", c.line, c.want, entry.V3.Level)
		}
	}
}

func TestV3Defaults(t *testing.T) {
	entry, err := parseLine("h user=u authpass=a privpass=p", 1, 161)
	if err != nil {
		t.Fatal(err)
	}
	if entry.V3.Auth != gosnmp.SHA {
		t.Errorf("default auth should be SHA (SHA-1), got %v", entry.V3.Auth)
	}
	if entry.V3.Priv != gosnmp.AES {
		t.Errorf("default priv should be AES, got %v", entry.V3.Priv)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct {
		line    string
		wantErr string
	}{
		{"10.0.0.1", "community= (v2c) or user= (v3)"},
		{"10.0.0.1 community=a user=b", "mutually exclusive"},
		{"10.0.0.1 community=a bogus=1", "unknown key"},
		{"10.0.0.1 community=a port=0", "invalid port"},
		{"10.0.0.1 community=a port=99999", "invalid port"},
		{"10.0.0.1 frag community=a", "expected key=value"},
		{"community=a", "first token must be a host"},
		{"h user=u level=authPriv authpass=a", "requires privpass="},
		{"h user=u level=authPriv privpass=p", "requires authpass="},
		{"h user=u authpass=a auth=SHA1024", "invalid auth protocol"},
		{"h user=u authpass=a privpass=p priv=DES3", "invalid priv protocol"},
		{"h user=u level=wide-open", "invalid level"},
		{`h community="unterminated`, "unterminated quote"},
	}
	for _, c := range cases {
		_, err := parseLine(c.line, 7, 161)
		if err == nil {
			t.Errorf("%q: expected error", c.line)
			continue
		}
		if !strings.Contains(err.Error(), c.wantErr) {
			t.Errorf("%q: error %q does not contain %q", c.line, err.Error(), c.wantErr)
		}
	}
}

func TestDuplicateIdentityRejected(t *testing.T) {
	path := writeHostsFile(t, `
10.0.0.1 community=a
10.0.0.1 community=b
`, 0600)
	if _, err := ParseHostsFile(path, 161); err == nil || !strings.Contains(err.Error(), "duplicate device identity") {
		t.Errorf("want duplicate identity error, got %v", err)
	}

	// Same host distinguished by name= is fine
	path = writeHostsFile(t, `
10.0.0.1 community=a name=fw-1
10.0.0.1 community=b name=fw-2
`, 0600)
	if _, err := ParseHostsFile(path, 161); err != nil {
		t.Errorf("name= should distinguish duplicate hosts: %v", err)
	}
}

func TestHostsFilePermsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission check is unix-only")
	}
	path := writeHostsFile(t, "10.0.0.1 community=a\n", 0644)
	_, err := ParseHostsFile(path, 161)
	if err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Errorf("world-readable hosts file must be refused with chmod hint, got %v", err)
	}
}

func TestCommentsAndBlanksIgnored(t *testing.T) {
	path := writeHostsFile(t, "\n# comment\n\n   \n10.0.0.1 community=a\n", 0600)
	entries, err := ParseHostsFile(path, 161)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("want 1 entry, got %d", len(entries))
	}
}
