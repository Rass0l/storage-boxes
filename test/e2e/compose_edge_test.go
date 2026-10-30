//go:build compose_e2e

package e2e

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// TestComposeEdgeTLS checks the `edge` nginx service:
//  1. It brought itself up with a self-signed cert (or the operator-
//     provided cert) — HTTPS on :8443 answers 200 on /healthz.
//  2. Plain HTTP on :8088 redirects to HTTPS (301) except for the
//     health probe.
//  3. Security headers the edge sets (HSTS, X-Content-Type-Options,
//     X-Frame-Options) are present on the HTTPS response.
//  4. The edge proxies /api/v1/healthz through to the api.
//  5. The edge proxies /s/{token} through to the share-gateway (a
//     missing token yields 404 from the gateway, not from the edge).
func TestComposeEdgeTLS(t *testing.T) {
	ensureSharedStack(t)

	httpsPort := envOr("EDGE_HTTPS_PORT", "8443")
	httpPort := envOr("EDGE_HTTP_PORT", "8088")
	httpsBase := fmt.Sprintf("https://localhost:%s", httpsPort)
	httpBase := fmt.Sprintf("http://localhost:%s", httpPort)

	// Self-signed cert in dev — skip verification.
	insecure := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		Timeout:   10 * time.Second,
	}
	noRedirect := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	waitUntil(t, 60*time.Second, func() bool {
		resp, err := insecure.Get(httpsBase + "/healthz")
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "edge HTTPS /healthz never returned 200")

	// (1) HTTPS /healthz → 200.
	resp, err := insecure.Get(httpsBase + "/healthz")
	if err != nil {
		t.Fatalf("https healthz: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("edge https healthz: %d %s", resp.StatusCode, body)
	}

	// (2) Plain HTTP redirects to HTTPS for non-health paths, and the
	//     redirect target includes the actual HTTPS port so the browser
	//     doesn't get stranded on :443 when the edge is published on
	//     a different host port.
	resp, err = noRedirect.Get(httpBase + "/shares")
	if err != nil {
		t.Fatalf("http redirect: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMovedPermanently && resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 301/302 redirect on plain HTTP, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if loc == "" || !strings.HasPrefix(loc, "https://") {
		t.Fatalf("expected https:// redirect target, got %q", loc)
	}
	// When the HTTPS port is non-default, the Location must include it.
	if httpsPort != "443" {
		wantPortSeg := ":" + httpsPort
		if !strings.Contains(loc, wantPortSeg) {
			t.Fatalf("redirect Location %q missing configured HTTPS port %s", loc, httpsPort)
		}
	}
	if !strings.HasSuffix(loc, "/shares") {
		t.Fatalf("redirect Location %q did not preserve the request URI", loc)
	}

	// (2b) Following the redirect through the insecure client must reach
	//      the edge HTTPS listener (not get a connection-refused on the
	//      wrong port).
	followed, err := insecure.Get(httpBase + "/shares")
	if err != nil {
		t.Fatalf("follow-redirect chain broke: %v", err)
	}
	followed.Body.Close()
	if followed.StatusCode >= 500 {
		t.Fatalf("follow-through 5xx: %d", followed.StatusCode)
	}

	// (3) Security headers on HTTPS.
	resp, err = insecure.Get(httpsBase + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, h := range []string{"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options"} {
		if resp.Header.Get(h) == "" {
			t.Fatalf("expected header %s on edge HTTPS response", h)
		}
	}

	// (4) Edge proxies /api/ to the api process.
	resp, err = insecure.Get(httpsBase + "/api/v1/healthz")
	if err != nil {
		t.Fatalf("edge → api healthz: %v", err)
	}
	resp.Body.Close()
	// api's /healthz may live at /healthz directly; we assert via /readyz-
	// equivalent which definitely proxies. /api/v1/auth/me unauth → 401.
	resp, err = insecure.Get(httpsBase + "/api/v1/auth/me")
	if err != nil {
		t.Fatalf("edge → api auth/me: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 through edge on unauth /api/v1/auth/me, got %d", resp.StatusCode)
	}

	// (5) Edge proxies /s/ to the share-gateway — bogus token → 404.
	resp, err = insecure.Get(httpsBase + "/s/token-that-does-not-exist")
	if err != nil {
		t.Fatalf("edge → share-gateway: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404 for bogus share token through edge, got %d", resp.StatusCode)
	}

	// (6) server_tokens off — Server header must not leak the nginx
	// version number.
	resp, err = insecure.Get(httpsBase + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	server := resp.Header.Get("Server")
	if strings.Contains(server, "/") {
		// "nginx/1.27.5" leaks; bare "nginx" is fine.
		t.Fatalf("Server header leaks version: %q", server)
	}

	// (7) Rate-limit on /s/ — fire a burst and expect at least one 429.
	// With 30r/s + burst 20 nodelay, 80 rapid probes to a bogus token
	// reliably overflow the bucket.
	seen429 := false
	for i := 0; i < 80; i++ {
		r, err := insecure.Get(httpsBase + "/s/rate-test-token")
		if err != nil {
			t.Fatalf("rate probe %d: %v", i, err)
		}
		r.Body.Close()
		if r.StatusCode == 429 {
			seen429 = true
			break
		}
	}
	if !seen429 {
		t.Fatal("edge rate-limit did not trigger on burst to /s/")
	}
}

func waitUntil(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("timeout waiting %s: %s", d, msg)
}

func envOr(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}
