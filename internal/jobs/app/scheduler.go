package app

import "context"

type Scheduler interface {
	Run(ctx context.Context) error
}
