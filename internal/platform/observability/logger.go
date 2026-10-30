package observability

import (
	"log"
	"os"
)

type Logger interface {
	Infof(format string, args ...any)
	Errorf(format string, args ...any)
}

type StdLogger struct {
	base *log.Logger
}

func NewStdLogger(prefix string) *StdLogger {
	return &StdLogger{base: log.New(os.Stdout, prefix+" ", log.LstdFlags|log.LUTC)}
}

func (l *StdLogger) Infof(format string, args ...any) {
	l.base.Printf("INFO "+format, args...)
}

func (l *StdLogger) Errorf(format string, args ...any) {
	l.base.Printf("ERROR "+format, args...)
}
