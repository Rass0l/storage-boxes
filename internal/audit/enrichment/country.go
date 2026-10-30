package enrichment

import "net"

// CountryLookup resolves a client IP to a two-letter code. The default
// implementation classifies reserved ranges without doing real
// geolocation — that way the `country_code` column is populated
// honestly in dev/test without shipping a GeoIP2 database. Production
// deployments wire a real provider (MaxMind, ip2location, Cloudflare
// CF-IPCountry header) by supplying their own CountryLookup.
//
// Return values for the default impl:
//
//	"LO" — loopback (127.0.0.0/8, ::1, etc.)
//	"PR" — private (RFC1918, RFC4193, link-local, etc.)
//	""   — anything else (public IPs the default impl can't classify)
type CountryLookup interface {
	Lookup(ip string) string
}

// DefaultCountryLookup implements the classifier described on
// CountryLookup. Zero-value usable.
type DefaultCountryLookup struct{}

var _ CountryLookup = DefaultCountryLookup{}

func (DefaultCountryLookup) Lookup(raw string) string {
	if raw == "" {
		return ""
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return ""
	}
	if ip.IsLoopback() {
		return "LO"
	}
	if ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return "PR"
	}
	return ""
}

// StaticCountryLookup is a deterministic test helper: it returns the
// pre-seeded country code for any IP key, falling back to the supplied
// default. Use in audit/enrichment tests and in the public-share
// download tests so assertions don't depend on a live GeoIP DB.
type StaticCountryLookup struct {
	Table    map[string]string
	Fallback string
}

var _ CountryLookup = StaticCountryLookup{}

func (s StaticCountryLookup) Lookup(ip string) string {
	if code, ok := s.Table[ip]; ok {
		return code
	}
	return s.Fallback
}
