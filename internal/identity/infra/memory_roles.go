package infra

import (
	"context"

	"github.com/Rass0l/storage-boxes/internal/identity/app"
)

type StaticRoleEvaluator struct {
	RoleMap map[string]map[string]bool
}

var _ app.RoleEvaluator = StaticRoleEvaluator{}

func (e StaticRoleEvaluator) HasRole(ctx context.Context, userID, role string) (bool, error) {
	_ = ctx
	if roles, ok := e.RoleMap[userID]; ok {
		return roles[role], nil
	}
	return false, nil
}
