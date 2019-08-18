package config

import (
	"github.com/getsentry/sentry-go"
	"github.com/pkg/errors"
	"github.com/rs/zerolog"
	"os"
)

type LogOptions struct {
	Tags map[string]string
	Msg  string
}

type ErrLogger interface {
	Log(error, LogOptions)
}

type SentryHub struct {
	client *sentry.Client
}

func NewSentryHub(conf config) (*SentryHub, error) {
	opts := sentry.ClientOptions{
		Dsn: conf.Sentry.Dsn,
	}
	c, err := sentry.NewClient(opts)
	if err != nil {
		return nil, err
	}
	sh := SentryHub{
		client: c,
	}

	return &sh, nil
}

func (hub *SentryHub) GetLogger(tags map[string]string) *sentryLogger {
	scope := sentry.NewScope()
	for k, v := range tags {
		scope.SetTag(k, v)
	}
	h := sentry.NewHub(hub.client, scope)
	return &sentryLogger{
		h: h,
	}
}

type sentryLogger struct {
	h *sentry.Hub
}

func (l *sentryLogger) Log(err error, opts LogOptions) {
	l.h.Lock()
	defer l.h.Unlock()
	scope := l.h.PushScope()
	defer l.h.PopScope()
	for k, v := range opts.Tags {
		scope.SetTag(k, v)
	}
	l.h.CaptureException(errors.Wrap(err, opts.Msg))
}

type zeroLogger struct {
	l zerolog.Logger
}

func (l *zeroLogger) Log(err error, opts LogOptions) {
	ctx := l.l.With()
	for k, v := range opts.Tags {
		ctx = ctx.Str(k, v)
	}
	ctx.Logger().Err(err).Msg(opts.Msg)
}

func NewZeroLogger(tags map[string]string) ErrLogger {
	ctx := zerolog.New(os.Stderr).With().Timestamp()
	for k, v := range tags {
		ctx = ctx.Str(k, v)
	}
	l := ctx.Logger()
	return &zeroLogger{
		l: l,
	}
}

type errLogChain struct {
	loggers []ErrLogger
}

func (chain *errLogChain) Log(err error, opts LogOptions) {
	for _, l := range chain.loggers {
		l.Log(err, opts)
	}
}

func (chain *errLogChain) Add(el ErrLogger) {
	chain.loggers = append(chain.loggers, el)
}

func NewErrLogChain(loggers ...ErrLogger) *errLogChain {
	return &errLogChain{
		loggers: loggers,
	}
}
