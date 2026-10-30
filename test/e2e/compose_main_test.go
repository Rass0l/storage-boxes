//go:build compose_e2e

package e2e

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	code := m.Run()
	teardownSharedStack()
	os.Exit(code)
}
