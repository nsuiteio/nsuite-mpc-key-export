package errutil

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
)

type WrappedError struct {
	Cause      error
	StackTrace []string
}

func (e *WrappedError) String() string {
	lines := strings.Join(e.StackTrace, "\n")
	return fmt.Sprintf("%s\n%s", e.Cause.Error(), lines)
}

func (e *WrappedError) Error() string {
	return e.String()
}

func (e *WrappedError) Unwrap() error {
	return e.Cause
}
func Wrap(err error) error {
	if err == nil {
		return nil
	}
	var wrappedError *WrappedError
	if errors.As(err, &wrappedError) {
		return err
	}
	var stacks []string
	for i := 1; ; i++ {
		_, file, line, _ := runtime.Caller(i)
		if len(file) < 1 || line < 1 {
			break
		}
		stacks = append(stacks, fmt.Sprintf("%s:%d", file, line))
	}

	return &WrappedError{
		Cause:      err,
		StackTrace: stacks,
	}
}

// Unwrap はラップを再起的に剥がしてて、最後のエラーを返す
// ラップされてない場合は元のエラーを返す
func Unwrap(err error) error {
	if err == nil {
		return nil
	}
	cause := err
	for {
		next := errors.Unwrap(cause)
		if next == nil {
			break
		}
		cause = next
	}
	return cause
}
