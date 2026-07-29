package snmp

import "testing"

func TestEnterpriseNumber(t *testing.T) {
	cases := []struct {
		oid  string
		want uint32
	}{
		{".1.3.6.1.4.1.12356.101.1.10004", 12356},
		{"1.3.6.1.4.1.9.1.1234", 9}, // leading dot optional
		{".1.3.6.1.4.1.25461.2.3.36", 25461},
		{".1.3.6.1.2.1.1.1.0", 0}, // not under private enterprises
		{"", 0},
		{".1.3.6.1.4.1.notanumber.1", 0},
	}
	for _, c := range cases {
		if got := enterpriseNumber(c.oid); got != c.want {
			t.Errorf("enterpriseNumber(%q) = %d, want %d", c.oid, got, c.want)
		}
	}
}

func TestProfileVersionExtraction(t *testing.T) {
	cases := []struct {
		name     string
		oid      string // sysObjectID selecting the profile
		sysDescr string
		want     string
	}{
		{
			name:     "cisco ios",
			oid:      ".1.3.6.1.4.1.9.1.1045",
			sysDescr: "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2(4)M6, RELEASE SOFTWARE (fc1)",
			want:     "15.2(4)M6",
		},
		{
			name:     "cisco ios xe colon-less",
			oid:      ".1.3.6.1.4.1.9.1.2494",
			sysDescr: "Cisco IOS XE Software, Version 16.09.04",
			want:     "16.09.04",
		},
		{
			name:     "juniper junos",
			oid:      ".1.3.6.1.4.1.2636.1.1.1.2.96",
			sysDescr: "Juniper Networks, Inc. srx340 internet router, kernel JUNOS 21.4R3.15, Build date: 2023-02-15",
			want:     "21.4R3.15",
		},
		{
			name:     "mikrotik routeros",
			oid:      ".1.3.6.1.4.1.14988.1",
			sysDescr: "RouterOS 6.48.6 (long-term) CCR1009-7G-1C-1S+",
			want:     "6.48.6",
		},
		{
			name:     "sonicwall",
			oid:      ".1.3.6.1.4.1.8741.1",
			sysDescr: "SonicWALL TZ 400 (SonicOS Enhanced 6.5.4.7-83n)",
			want:     "6.5.4.7-83n",
		},
		{
			name:     "arubaos",
			oid:      ".1.3.6.1.4.1.14823.1.1.32",
			sysDescr: "ArubaOS (MODEL: Aruba7010), Version 8.6.0.4",
			want:     "8.6.0.4",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			profile, ok := profileFor(c.oid)
			if !ok {
				t.Fatalf("no profile for %s", c.oid)
			}
			got := versionFromDescr(&profile, c.sysDescr)
			if got != c.want {
				t.Errorf("versionFromDescr = %q, want %q", got, c.want)
			}
		})
	}
}

func TestGenericVersionExtraction(t *testing.T) {
	cases := []struct {
		sysDescr string
		want     string
	}{
		// unknown-vendor devices fall to the generic patterns
		{"Some Appliance OS, Version: 4.2.1-build77", "4.2.1-build77"},
		{"WidgetOS v3.14.159 on WidgetBox 9000", "3.14.159"},
		{"Linux gw01 5.15.0-91-generic #101-Ubuntu SMP x86_64", "5.15.0-91-generic"},
		{"No digits here at all", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := versionFromDescr(nil, c.sysDescr); got != c.want {
			t.Errorf("versionFromDescr(nil, %q) = %q, want %q", c.sysDescr, got, c.want)
		}
	}
}

func TestCleanVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"v7.2.5,build1517", "7.2.5"}, // Fortinet fgSysVersion form
		{" 9.1.3 ", "9.1.3"},
		{"15.2(4)M6.", "15.2(4)M6"},
		{"R81.10", "R81.10"}, // Check Point svnVersion form survives
	}
	for _, c := range cases {
		if got := cleanVersion(c.in); got != c.want {
			t.Errorf("cleanVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestProfileMetadata(t *testing.T) {
	// Every profile must emit a category the server's CHECK constraint accepts
	valid := map[string]bool{
		"firewall": true, "load_balancer": true, "vpn_gateway": true,
		"hypervisor": true, "virtualization_mgmt": true, "router": true,
		"switch": true, "wireless": true, "storage": true, "backup": true,
		"email_security": true, "web_proxy": true, "out_of_band": true,
		"ot_ics": true, "other": true,
	}
	for ent, p := range profiles {
		if !valid[p.Category] {
			t.Errorf("profile %d: category %q not in the server CHECK list", ent, p.Category)
		}
		if p.Vendor == "" || p.Product == "" {
			t.Errorf("profile %d: vendor/product must be non-empty", ent)
		}
		if len(p.VersionOIDs) == 0 && p.DescrRegex == nil {
			t.Errorf("profile %d: needs a version OID or a sysDescr regex", ent)
		}
	}
}

func TestTruncateRunes(t *testing.T) {
	if got := truncateRunes("héllo wörld", 5); got != "héllo" {
		t.Errorf("truncateRunes rune-safety broken: %q", got)
	}
	if got := truncateRunes("short", 100); got != "short" {
		t.Errorf("no-op truncation broken: %q", got)
	}
}
