package app

import "context"

type RoleEvaluator interface {
	HasRole(ctx context.Context, userID, role string) (bool, error)
}
