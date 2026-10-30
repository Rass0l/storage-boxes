package integration

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestBaseComposeExposesOnlyEdgePorts is the production-shape guard:
// in the base docker-compose.yml, the ONLY service that carries a
// `ports:` stanza must be `edge`. Everything else (postgres, api,
// worker, share-gateway, frontend) must reach the host through the
// edge. The dev overlay (docker-compose.dev.yml) is the only place
// allowed to re-publish internal ports for local debugging.
//
// Kept as a line-by-line parse because running `docker compose config`
// would bring docker into the unit-test path. Regression-guards a
// common accident: copying an existing service's block and keeping
// the `ports:` stanza that came with it.
func TestBaseComposeExposesOnlyEdgePorts(t *testing.T) {
	path := filepath.Join("..", "..", "deployments", "compose", "docker-compose.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(raw), "\n")

	currentService := ""
	for i, line := range lines {
		// Track which service block we're inside. Service names sit at
		// two-space indent under `services:`. The compose file only
		// declares one top-level services: map; we rely on the
		// two-space indent convention.
		if len(line) > 2 && line[0] != ' ' && line[0] != '#' {
			// top-level key (services:, volumes:, etc.)
			currentService = ""
			continue
		}
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			trimmed := strings.TrimSpace(line)
			if strings.HasSuffix(trimmed, ":") && !strings.HasPrefix(trimmed, "#") {
				currentService = strings.TrimSuffix(trimmed, ":")
				continue
			}
		}
		// `ports:` stanza inside a service block — must be `edge`.
		if strings.TrimSpace(line) == "ports:" && currentService != "" {
			if currentService != "edge" {
				t.Fatalf("docker-compose.yml line %d: service %q has a ports: stanza in the production shape; only `edge` is allowed to publish host ports. Move the stanza into docker-compose.dev.yml.", i+1, currentService)
			}
		}
	}
}

// TestDevOverlayAddsInternalPorts proves the dev override re-publishes
// every internal service the test suite and local debugging rely on.
// If someone deletes a port there the test suite will still compile
// but pg-direct tests would fail mysteriously at runtime — catch it
// here instead.
func TestDevOverlayAddsInternalPorts(t *testing.T) {
	path := filepath.Join("..", "..", "deployments", "compose", "docker-compose.dev.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	required := []string{
		`"5432:5432"`, // postgres
		`"8082:8082"`, // api
		`"8083:8083"`, // worker
		`"8084:8084"`, // share-gateway
		`"5173:80"`,   // frontend
	}
	for _, p := range required {
		if !strings.Contains(src, p) {
			t.Fatalf("dev overlay missing %s — pg-direct tests / local debugging will fail", p)
		}
	}
}
