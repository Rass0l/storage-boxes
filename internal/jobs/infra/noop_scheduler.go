package infra

import "context"

type NoopScheduler struct{}

func (NoopScheduler) Run(ctx context.Context) error {
	_ = ctx
	return nil
}
