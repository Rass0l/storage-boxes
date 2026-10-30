package infra

import "github.com/Rass0l/storage-boxes/internal/jobs/app"

type StaticRegistry struct {
	Items []app.Handler
}

func (r StaticRegistry) Handlers() []app.Handler {
	return r.Items
}
