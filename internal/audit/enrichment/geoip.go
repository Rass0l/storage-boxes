package enrichment

type GeoIPLookup interface {
	Lookup(ip string) (map[string]string, error)
}
