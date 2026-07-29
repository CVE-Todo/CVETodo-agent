package snmp

import (
	"regexp"
	"strconv"
	"strings"
)

// maxSysDescrRunes bounds the sysDescr we report; some devices return
// multi-paragraph banners
const maxSysDescrRunes = 1024

// unknownVersion is reported when no version could be determined. The server
// requires a non-blank version; an unknown-version row is inventory-only safe
// because CVE matching needs a catalog product link and a comparable version.
const unknownVersion = "unknown"

// Generic sysDescr version patterns, tried in order once vendor-specific
// extraction has failed
var genericVersionRegexes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bversion[:\s]+v?([0-9][\w.\-()]*)`),
	regexp.MustCompile(`\bv?([0-9]+\.[0-9]+[\w.\-]*)`),
}

// sysObjectID prefix for IANA private enterprises
const enterprisePrefix = ".1.3.6.1.4.1."

// enterpriseNumber extracts the IANA private-enterprise number from a
// sysObjectID like .1.3.6.1.4.1.12356.101.1.1234; returns 0 when the OID is
// not under the private-enterprises arc.
func enterpriseNumber(sysObjectID string) uint32 {
	oid := sysObjectID
	if !strings.HasPrefix(oid, ".") {
		oid = "." + oid
	}
	rest, ok := strings.CutPrefix(oid, enterprisePrefix)
	if !ok {
		return 0
	}
	num, _, _ := strings.Cut(rest, ".")
	n, err := strconv.ParseUint(num, 10, 32)
	if err != nil {
		return 0
	}
	return uint32(n)
}

// profileFor returns the vendor profile for a sysObjectID, if known
func profileFor(sysObjectID string) (vendorProfile, bool) {
	p, ok := profiles[enterpriseNumber(sysObjectID)]
	return p, ok
}

// versionFromDescr applies a profile's regex (when present) then the generic
// patterns to a sysDescr string; returns "" when nothing matches.
func versionFromDescr(profile *vendorProfile, sysDescr string) string {
	if sysDescr == "" {
		return ""
	}
	if profile != nil && profile.DescrRegex != nil {
		if m := profile.DescrRegex.FindStringSubmatch(sysDescr); m != nil {
			return cleanVersion(m[1])
		}
	}
	for _, re := range genericVersionRegexes {
		if m := re.FindStringSubmatch(sysDescr); m != nil {
			return cleanVersion(m[1])
		}
	}
	return ""
}

// cleanVersion tidies a raw version token: strips a leading "v", trailing
// punctuation, and anything after a comma (Fortinet reports "v7.2.5,build1517").
func cleanVersion(raw string) string {
	v := strings.TrimSpace(raw)
	v, _, _ = strings.Cut(v, ",")
	v = strings.TrimPrefix(v, "v")
	v = strings.TrimRight(v, ".-:")
	return strings.TrimSpace(v)
}

// truncateRunes caps s at n runes
func truncateRunes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}
