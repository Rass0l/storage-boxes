package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// renderNginxConf replicates the sed-substitution the edge container's
// entrypoint runs at boot: replace `:__EDGE_HTTPS_PORT__` with the
// configured host port (or "" when HTTPS is on the standard 443). Kept
// in lock-step with docker-compose.yml's entrypoint script; any change
// to one must be mirrored in the other.
func renderNginxConf(template, httpsPort string) string {
	if httpsPort == "" {
		httpsPort = "443"
	}
	portSeg := ":" + httpsPort
	if httpsPort == "443" {
		portSeg = ""
	}
	return strings.ReplaceAll(template, ":__EDGE_HTTPS_PORT__", portSeg)
}

// TestEdgeNginxRedirectRendering proves the template + substitution the
// entrypoint performs yields a redirect that preserves the host and
// routes to the right HTTPS port. It's a fast, docker-less guard for
// the same behavior that TestComposeEdgeTLS verifies against the live
// stack.
func TestEdgeNginxRedirectRendering(t *testing.T) {
	tpl, err := os.ReadFile(filepath.Join("..", "..", "deployments", "compose", "edge", "nginx.conf"))
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	raw := string(tpl)

	// The template must carry the placeholder (so the entrypoint has
	// something to substitute) and must NOT emit a bare `$host` redirect
	// that strips the port.
	if !strings.Contains(raw, ":__EDGE_HTTPS_PORT__") {
		t.Fatal("nginx.conf is missing the :__EDGE_HTTPS_PORT__ placeholder; redirect will drop the port")
	}

	cases := []struct {
		name, port, wantHostRedirect string
	}{
		{"dev compose default", "8443", "return 301 https://$edge_host_only:8443$request_uri"},
		{"prod standard HTTPS", "443", "return 301 https://$edge_host_only$request_uri"},
		{"alt high port", "9443", "return 301 https://$edge_host_only:9443$request_uri"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rendered := renderNginxConf(raw, tc.port)
			if !strings.Contains(rendered, tc.wantHostRedirect) {
				t.Fatalf("rendered nginx.conf for port %s missing redirect %q\n\nfull:\n%s",
					tc.port, tc.wantHostRedirect, rendered)
			}
			// A residual placeholder means the substitution pattern
			// drifted; catch it here instead of in a compose run.
			if strings.Contains(rendered, "__EDGE_HTTPS_PORT__") {
				t.Fatal("rendered nginx.conf still contains __EDGE_HTTPS_PORT__ placeholder")
			}
		})
	}
}

// TestEdgeEntrypointContract checks the docker-compose entrypoint script
// carries the two invariants the render test relies on: the sed
// substitution pattern and the "when HTTPS is 443, collapse the port
// segment" branch.
func TestEdgeEntrypointContract(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deployments", "compose", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, must := range []string{
		`:__EDGE_HTTPS_PORT__`,
		`sed "s|:__EDGE_HTTPS_PORT__|`,
		`if [ "$$port" = "443" ]`,
		`exec nginx -g 'daemon off;'`,
	} {
		if !strings.Contains(s, must) {
			t.Fatalf("docker-compose.yml entrypoint missing %q; render test and live container are out of sync", must)
		}
	}
}

// TestEdgeNginxForwardsForwardedHeaders asserts the proxy blocks for
// /api/ and /s/ set X-Forwarded-For + X-Forwarded-Proto, which the
// audit enrichment and trusted-proxies logic rely on.
func TestEdgeNginxForwardsForwardedHeaders(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deployments", "compose", "edge", "nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	for _, must := range []string{
		`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`,
		`proxy_set_header X-Forwarded-Proto https`,
		`location /api/`,
		`location /s/`,
		`add_header Strict-Transport-Security`,
	} {
		if !strings.Contains(s, must) {
			t.Fatalf("nginx.conf missing required directive %q", must)
		}
	}
}

// TestEdgeNginxHardeningDirectives locks in the security-hardening
// baseline so a config regression is flagged at unit-test speed
// instead of on the compose smoke run.
func TestEdgeNginxHardeningDirectives(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "deployments", "compose", "edge", "nginx.conf"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(raw)
	required := []struct{ name, needle string }{
		{"server_tokens off", `server_tokens off`},
		{"TLS 1.3 only", `ssl_protocols       TLSv1.3`},
		{"session tickets off", `ssl_session_tickets off`},
		{"CSP header", `add_header Content-Security-Policy`},
		{"Permissions-Policy header", `add_header Permissions-Policy`},
		{"share rate-limit zone", `limit_req_zone $binary_remote_addr zone=share_req`},
		{"share rate-limit applied", `limit_req zone=share_req`},
		{"429 status for rate limit", `limit_req_status 429`},
		{"proxy_buffering off for /s/", `proxy_buffering off`},
		{"long share timeout", `proxy_read_timeout 300s`},
	}
	for _, req := range required {
		if !strings.Contains(s, req.needle) {
			t.Fatalf("nginx.conf missing %s (%q)", req.name, req.needle)
		}
	}
	for _, forbidden := range []string{
		`TLSv1.0`, `TLSv1.1`,
		`HIGH:!aNULL:!MD5`,
	} {
		if strings.Contains(s, forbidden) {
			t.Fatalf("nginx.conf must not contain legacy directive %q", forbidden)
		}
	}
}
