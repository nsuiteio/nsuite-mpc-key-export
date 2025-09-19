package logutil

import (
	"context"
	"fmt"
	"log/slog"
	"sync/atomic"
)

type (
	key int

	LogByLevel interface {
		Debug(msg string, attrs ...any)
		Info(msg string, attrs ...any)
		Warn(msg string, attrs ...any)
		Error(msg string, attrs ...any)
	}
	Logger interface {
		LogByLevel
		With(attrs ...any) Logger
	}

	Prefixed struct {
		prefix string
		logger *slog.Logger
	}
)

const (
	loggerKey key = iota
)

var (
	defaultLogger = atomic.Pointer[Prefixed]{}
)

func Default() Logger {
	if logger := defaultLogger.Load(); logger != nil {
		return logger
	}
	defaultLogger.CompareAndSwap(nil, &Prefixed{
		prefix: "",
		logger: slog.Default(),
	})
	return defaultLogger.Load()
}

func Setup(
	ctx context.Context,
	prefix string,
	attrs ...*slog.Attr,
) context.Context {
	ukLogger := Get(ctx)
	prev, ok := ukLogger.(*Prefixed)
	if !ok {
		var vs []any
		for _, attr := range attrs {
			vs = append(vs, attr)
		}
		logger := ukLogger.With(vs...)
		return Set(ctx, logger)
	}
	nextPrefix := prev.prefix
	if len(nextPrefix) > 0 {
		nextPrefix = fmt.Sprintf("%s/%s", nextPrefix, prefix)
	} else {
		nextPrefix = prefix
	}

	anyAttrs := make([]any, 0, len(attrs))
	for _, attr := range attrs {
		anyAttrs = append(anyAttrs, attr)
	}
	anyAttrs = append(anyAttrs, slog.String("logger", nextPrefix))
	logger := slog.Default().With(anyAttrs...)
	next := &Prefixed{
		prefix: nextPrefix,
		logger: logger,
	}
	return Set(ctx, next)
}

// SetDefault は、指定されたコンテキストのロガーをデフォルトのロガーに設定します。
// コンテキストにロガーが設定されていない場合は何もしません。
func SetDefault(ctx context.Context) {
	if prefixed, ok := Get(ctx).(*Prefixed); ok {
		defaultLogger.Store(prefixed)
	}
}

func (w *Prefixed) With(attrs ...any) Logger {
	next := w.logger.With(attrs...)
	return &Prefixed{
		prefix: w.prefix,
		logger: next,
	}
}

func (w *Prefixed) Debug(msg string, attrs ...any) {
	w.logger.Debug(msg, attrs...)
}

func (w *Prefixed) Info(msg string, attrs ...any) {
	w.logger.Info(msg, attrs...)
}

func (w *Prefixed) Warn(msg string, attrs ...any) {
	w.logger.Warn(msg, attrs...)
}

func (w *Prefixed) Error(msg string, attrs ...any) {
	w.logger.Error(msg, attrs...)
}

func Set(ctx context.Context, logger LogByLevel) context.Context {
	return context.WithValue(ctx, loggerKey, logger)
}

func Get(ctx context.Context) Logger {
	if logger, ok := ctx.Value(loggerKey).(Logger); ok {
		return logger
	}
	return Default()
}
