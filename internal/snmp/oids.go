package snmp

import (
	"regexp"
	"strings"
)

// Standard MIB-II / ENTITY-MIB OIDs
const (
	oidSysDescr    = ".1.3.6.1.2.1.1.1.0"
	oidSysObjectID = ".1.3.6.1.2.1.1.2.0"
	oidSysName     = ".1.3.6.1.2.1.1.5.0"
	// entPhysicalSoftwareRev column; walked for the first non-empty value
	oidEntPhysicalSoftwareRev = ".1.3.6.1.2.1.47.1.1.1.1.10"
)

// vendorProfile describes how to identify a vendor's devices and extract the
// running firmware version. Vendor/Product are emitted in forms the server's
// vendor_aliases/product_aliases tables resolve to catalog entries; Category
// must be one of the team_appliances category CHECK values.
type vendorProfile struct {
	Vendor      string
	Product     string
	Category    string
	VersionOIDs []string       // vendor version OIDs, tried in order
	DescrRegex  *regexp.Regexp // version out of sysDescr
	// RefineProduct optionally narrows Product using sysDescr (e.g. Cisco
	// IOS vs IOS XE, which are separate catalog products)
	RefineProduct func(sysDescr string) string
}

// profiles is keyed by the IANA private-enterprise number parsed from
// sysObjectID (.1.3.6.1.4.1.<enterprise>...). A wrong or missing version OID
// degrades gracefully to the sysDescr regex, then the ENTITY-MIB fallback.
var profiles = map[uint32]vendorProfile{
	// Cisco: no universal version OID across IOS/IOS-XE/NX-OS; sysDescr
	// reliably carries "Version 15.2(4)M7" / "Version 16.09.04"
	9: {
		Vendor:     "cisco",
		Product:    "ios",
		Category:   "router",
		DescrRegex: regexp.MustCompile(`Version[ :]+([0-9][\w.():-]*[\w)])`),
		RefineProduct: func(sysDescr string) string {
			// "ios" and "ios_xe" are separate catalog products
			if strings.Contains(sysDescr, "IOS XE") || strings.Contains(sysDescr, "IOS-XE") {
				return "ios_xe"
			}
			return ""
		},
	},
	// Check Point: svnVersion (SVN-PRODUCTS-MIB)
	2620: {
		Vendor:      "checkpoint",
		Product:     "Gaia",
		Category:    "firewall",
		VersionOIDs: []string{".1.3.6.1.4.1.2620.1.6.4.1.0"},
	},
	// Juniper: sysDescr like "Juniper Networks, Inc. srx340 ... JUNOS 21.4R3.15 ..."
	2636: {
		Vendor:     "juniper",
		Product:    "junos",
		Category:   "router",
		DescrRegex: regexp.MustCompile(`JUNOS ([\w.\-]+)`),
	},
	// F5: sysProductVersion (F5-BIGIP-SYSTEM-MIB)
	3375: {
		Vendor:      "f5",
		Product:     "BIG-IP",
		Category:    "load_balancer",
		VersionOIDs: []string{".1.3.6.1.4.1.3375.2.1.4.2.0"},
	},
	// SonicWall: sonicSysFirmwareVersion, sysDescr fallback
	8741: {
		Vendor:      "sonicwall",
		Product:     "SonicOS",
		Category:    "firewall",
		VersionOIDs: []string{".1.3.6.1.4.1.8741.2.1.1.3.0"},
		DescrRegex:  regexp.MustCompile(`SonicOS[A-Za-z ]*([0-9][\w.\-]*)`),
	},
	// Fortinet: fgSysVersion (FORTINET-FORTIGATE-MIB), e.g. "v7.2.5,build1517"
	12356: {
		Vendor:      "fortinet",
		Product:     "FortiOS",
		Category:    "firewall",
		VersionOIDs: []string{".1.3.6.1.4.1.12356.101.4.1.1.0"},
	},
	// Aruba (HPE): sysDescr like "ArubaOS (MODEL: Aruba7010), Version 8.6.0.4"
	14823: {
		Vendor:     "arubanetworks",
		Product:    "ArubaOS",
		Category:   "wireless",
		DescrRegex: regexp.MustCompile(`Version ([0-9][\w.\-]*)`),
	},
	// MikroTik: mtxrLicVersion returns e.g. "6.48.6"; sysDescr is "RouterOS <model>"
	14988: {
		Vendor:      "mikrotik",
		Product:     "RouterOS",
		Category:    "router",
		VersionOIDs: []string{".1.3.6.1.4.1.14988.1.1.4.4.0"},
		DescrRegex:  regexp.MustCompile(`RouterOS ([0-9][\w.]*)`),
	},
	// Palo Alto: panSysSwVersion (PAN-COMMON-MIB)
	25461: {
		Vendor:      "paloaltonetworks",
		Product:     "PAN-OS",
		Category:    "firewall",
		VersionOIDs: []string{".1.3.6.1.4.1.25461.2.1.2.1.1.0"},
	},
}
