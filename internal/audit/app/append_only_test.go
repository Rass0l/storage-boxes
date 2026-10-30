package app

import (
	"reflect"
	"strings"
	"testing"
)

// TestAuditRepositoryIsAppendOnly is a compile-time guardrail: the
// AuditRepository interface must not expose any Update / Delete / Edit
// methods. The pg trigger in migration 007 is the enforcement at the DB
// layer; this test stops the interface from quietly gaining a mutating
// method in code review.
func TestAuditRepositoryIsAppendOnly(t *testing.T) {
	iface := reflect.TypeOf((*AuditRepository)(nil)).Elem()
	for i := 0; i < iface.NumMethod(); i++ {
		name := iface.Method(i).Name
		lower := strings.ToLower(name)
		for _, forbidden := range []string{"update", "delete", "edit", "remove", "set"} {
			if strings.HasPrefix(lower, forbidden) {
				t.Fatalf("AuditRepository.%s violates append-only contract", name)
			}
		}
	}
}
