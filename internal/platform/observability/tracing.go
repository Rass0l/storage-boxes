package observability

type Tracer interface {
	Start(name string) func()
}
