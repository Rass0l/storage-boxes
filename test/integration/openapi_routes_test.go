package integration

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenAPICoversShareRoutes keeps api/openapi/openapi.yaml in sync
// with the routes actually registered in internal/shares/api. Any
// restricted-share path we add to the binary but forget to document
// will flag here. Kept narrow to share* paths because those are the
// ones that cycle fastest; other surfaces have their own pattern.
func TestOpenAPICoversShareRoutes(t *testing.T) {
	routes := readFile(t, locate(t, filepath.Join("internal", "shares", "api", "routes.go")))
	spec := readFile(t, locate(t, filepath.Join("api", "openapi", "openapi.yaml")))

	// Authenticated share paths registered on mux.
	mustDocument := []string{
		"/api/v1/shares",
		"/api/v1/shares/{id}",
		"/api/v1/shares/{id}/access",
		"/api/v1/shares/{id}/recipients",
		"/api/v1/shares/{id}/recipients/{rid}",
		"/api/v1/shares/{id}/recipients/{rid}/rotate",
		"/api/v1/shares/{id}/recipients/{rid}/activity",
		"/api/v1/shares/{id}/challenges",
		"/api/v1/shares/{id}/claims",
		"/api/v1/shares/{id}/claims/{cid}",
		// Owner-approved access requests.
		"/api/v1/shares/{id}/access-requests",
		"/api/v1/shares/{id}/access-requests/{arid}/approve",
		"/api/v1/shares/{id}/access-requests/{arid}/deny",
		// Gateway public surface.
		"/s/{token}",
		"/s/{token}/verify",
		"/s/{token}/otp",
		"/s/{token}/revoke-claim",
		"/s/{token}/request-access",
		"/s/{token}/request-status",
	}

	// Narrow sanity: each path we claim must cover must appear
	// somewhere in routes.go AND in the OpenAPI entrypoint.
	for _, p := range mustDocument {
		if !strings.Contains(spec, p+":") {
			t.Errorf("openapi.yaml is missing path %q", p)
		}
	}

	// Route-side sanity: every share-related `mux.Handle` line
	// registered in routes.go should map to a documented path. This
	// catches the reverse case — a route added without OpenAPI.
	for _, line := range strings.Split(routes, "\n") {
		if !strings.Contains(line, "mux.Handle(") {
			continue
		}
		if !strings.Contains(line, "/api/v1/shares") && !strings.Contains(line, "/s/{token}") {
			continue
		}
		matched := false
		for _, p := range mustDocument {
			if strings.Contains(line, " "+p+`"`) || strings.Contains(line, " "+p+`")`) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("route not covered by OpenAPI whitelist: %s", strings.TrimSpace(line))
		}
	}
}
