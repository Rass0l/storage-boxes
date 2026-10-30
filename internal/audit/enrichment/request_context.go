package enrichment

import (
	"net"
	"net/http"
	"strings"
)

// RequestContext captures the transport-level attributes audit records care
// about. Populated by the enrichment middleware at the edge of each runtime
// (api, share-gateway) so business code never touches the raw *http.Request.
type RequestContext struct {
	RemoteIP  string
	UserAgent string
	Referer   string
	RequestID string
}

// Extract pulls RequestContext from an *http.Request. If trustedProxies is
// non-empty and RemoteAddr belongs to one of them, X-Forwarded-For's
// left-most entry is used instead. Unset fields stay empty.
func Extract(r *http.Request, trustedProxies []string) RequestContext {
	rc := RequestContext{
		UserAgent: strings.TrimSpace(r.Header.Get("User-Agent")),
		Referer:   strings.TrimSpace(r.Header.Get("Referer")),
		RequestID: strings.TrimSpace(r.Header.Get("X-Request-Id")),
	}
	ip := clientIP(r, trustedProxies)
	rc.RemoteIP = ip
	return rc
}

func clientIP(r *http.Request, trustedProxies []string) string {
	direct := hostOnly(r.RemoteAddr)
	if len(trustedProxies) > 0 && isTrusted(direct, trustedProxies) {
		xff := r.Header.Get("X-Forwarded-For")
		if xff != "" {
			parts := strings.Split(xff, ",")
			if cand := strings.TrimSpace(parts[0]); cand != "" {
				return cand
			}
		}
	}
	return direct
}

func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

func isTrusted(ip string, trusted []string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	for _, entry := range trusted {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if _, cidr, err := net.ParseCIDR(entry); err == nil {
			if cidr.Contains(parsed) {
				return true
			}
			continue
		}
		if entry == ip {
			return true
		}
	}
	return false
}
