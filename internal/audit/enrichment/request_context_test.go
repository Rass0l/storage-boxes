package enrichment

import (
	"net/http/httptest"
	"testing"

	"github.com/Rass0l/storage-boxes/internal/audit/domain"
)

func TestExtractIgnoresXFFFromUntrusted(t *testing.T) {
	r := httptest.NewRequest("GET", "/s/tok", nil)
	r.RemoteAddr = "198.51.100.10:5555"
	r.Header.Set("X-Forwarded-For", "203.0.113.1")
	rc := Extract(r, nil)
	if rc.RemoteIP != "198.51.100.10" {
		t.Fatalf("want direct peer IP, got %q", rc.RemoteIP)
	}
}

func TestExtractHonorsXFFFromTrustedCIDR(t *testing.T) {
	r := httptest.NewRequest("GET", "/s/tok", nil)
	r.RemoteAddr = "172.17.0.5:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	rc := Extract(r, []string{"172.16.0.0/12"})
	if rc.RemoteIP != "203.0.113.7" {
		t.Fatalf("want left-most XFF, got %q", rc.RemoteIP)
	}
}

func TestExtractCapturesUserAgentAndRequestID(t *testing.T) {
	r := httptest.NewRequest("GET", "/s/tok", nil)
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("User-Agent", "curl/8.0")
	r.Header.Set("X-Request-Id", "req_abc")
	rc := Extract(r, nil)
	if rc.UserAgent != "curl/8.0" || rc.RequestID != "req_abc" {
		t.Fatalf("ua/req_id not captured: %+v", rc)
	}
}

func TestHeuristicRiskScorer(t *testing.T) {
	s := HeuristicRiskScorer{}
	// Clean browser, no red flags → info.
	score, sev := s.Score(map[string]string{"remote_ip": "203.0.113.1", "user_agent": "Mozilla/5.0"})
	if sev != domain.SeverityInfo || score >= 20 {
		t.Fatalf("clean request: score=%d sev=%s", score, sev)
	}
	// curl + near-cap → elevated.
	score, sev = s.Score(map[string]string{
		"remote_ip": "203.0.113.1", "user_agent": "curl/8.6", "near_download_cap": "true",
	})
	if score < 20 {
		t.Fatalf("expected curl+near-cap to raise score; got %d %s", score, sev)
	}
	// Missing UA + missing IP + new-IP → elevated or high.
	score, sev = s.Score(map[string]string{"new_ip_for_subject": "true"})
	if score < 40 || (sev != domain.SeverityElevated && sev != domain.SeverityHigh) {
		t.Fatalf("expected elevated+, got %d %s", score, sev)
	}
}
