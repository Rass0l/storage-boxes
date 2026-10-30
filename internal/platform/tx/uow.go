package tx

import "context"

type UnitOfWork interface {
	Within(ctx context.Context, fn func(context.Context) error) error
}

type NoopUnitOfWork struct{}

func (NoopUnitOfWork) Within(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}
