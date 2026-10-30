package observability

type Counter interface {
	Inc()
}

type Histogram interface {
	Observe(v float64)
}
