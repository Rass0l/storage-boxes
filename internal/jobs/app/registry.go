package app

type Handler interface {
	Name() string
}

type Registry interface {
	Handlers() []Handler
}
