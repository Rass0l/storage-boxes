GOFLAGS ?=
PKG := ./...
COMPOSE_DIR := deployments/compose

.PHONY: fmt lint test unit integration migration-test web-check verify-counts \
        compose-up compose-up-dev compose-down compose-logs compose-e2e compose-ui-e2e

fmt:
	gofmt -w $(shell find . -name '*.go' -not -path './vendor/*')

lint:
	./scripts/lint.sh

test: unit integration migration-test web-check

unit:
	./scripts/test-unit.sh

integration:
	./scripts/test-integration.sh

migration-test:
	./scripts/test-migrations.sh

web-check:
	./scripts/web-check.sh

verify-counts:
	./scripts/verify-stage1-counts.sh

# Compose helpers --------------------------------------------------------
#
# The base docker-compose.yml is production-shaped: only the `edge`
# service publishes host ports. `compose-up-dev` layers
# docker-compose.dev.yml on top to also expose the internal ports
# (postgres :5432, api :8082, worker :8083, share-gateway :8084,
# frontend :5173) for debugging. compose-e2e uses the dev overlay
# because the pg-direct test suite needs direct Postgres access.

COMPOSE_DEV_OVERRIDE := -f docker-compose.yml -f docker-compose.dev.yml

compose-up:
	cd $(COMPOSE_DIR) && docker compose up -d --build

compose-up-dev:
	cd $(COMPOSE_DIR) && docker compose $(COMPOSE_DEV_OVERRIDE) up -d --build

compose-down:
	cd $(COMPOSE_DIR) && docker compose down -v --remove-orphans

compose-logs:
	cd $(COMPOSE_DIR) && docker compose logs --tail=200 -f

# Full compose-backed end-to-end tests. Requires docker. Uses the dev
# overlay so pg-direct tests can reach Postgres on localhost:5432 and
# the frontend smoke test can hit :5173 without going through the edge.
#   * TestComposeStackMajorFlows    — auth + box + file flows against the
#     live API, plus a frontend shell check.
#   * TestComposeRestartDurability  — creates data, restarts the api
#     container, re-verifies reads decrypt correctly, and asserts the
#     expected Postgres rows shape (absolute expiry, encrypted BMK, etc).
#   * TestComposeEdgeTLS             — HTTPS + redirect + rate-limit via
#     the edge.
#   * TestPG*                        — direct pg-backed tests of the
#     store implementations (unique constraints, FK cascades, tx
#     atomicity, session/unlock sweep, BoxRepository contract).
compose-e2e:
	COMPOSE_E2E=1 COMPOSE_FILES="$(COMPOSE_DEV_OVERRIDE)" \
	  go test -tags=compose_e2e ./test/e2e/... -run 'TestCompose.*|TestPG.*' -v -timeout 15m

# Real browser flows (Playwright). Requires docker + the compose stack
# already running (make compose-up).
compose-ui-e2e:
	@cd web && PLAYWRIGHT_E2E=1 npx playwright test
