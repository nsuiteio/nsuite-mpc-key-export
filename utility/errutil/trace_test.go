package errutil

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWrap_NilError(t *testing.T) {
	result := Wrap(nil)
	assert.Nil(t, result)
}

func TestWrap_RegularError(t *testing.T) {
	originalErr := errors.New("test error")
	result := Wrap(originalErr)

	assert.NotNil(t, result)

	wrappedErr, ok := result.(*WrappedError)
	assert.True(t, ok, "Result should be a WrappedError")
	assert.Equal(t, originalErr, wrappedErr.Cause)
	assert.NotEmpty(t, wrappedErr.StackTrace, "Stack trace should not be empty")

	// Check that stack trace contains this test file
	found := false
	for _, trace := range wrappedErr.StackTrace {
		if strings.Contains(trace, "trace_test.go") {
			found = true
			break
		}
	}
	assert.True(t, found, "Stack trace should contain trace_test.go")
}

func TestWrap_AlreadyWrappedError(t *testing.T) {
	originalErr := errors.New("original error")
	wrappedOnce := Wrap(originalErr)
	wrappedTwice := Wrap(wrappedOnce)

	// Should return the same error, not wrap it again
	assert.Equal(t, wrappedOnce, wrappedTwice)
}

func TestWrappedError_Error(t *testing.T) {
	originalErr := errors.New("test error")
	wrapped := Wrap(originalErr).(*WrappedError)

	errorString := wrapped.Error()
	assert.Contains(t, errorString, "test error")
	assert.Contains(t, errorString, "trace_test.go")
}

func TestWrappedError_String(t *testing.T) {
	originalErr := errors.New("test error")
	wrapped := Wrap(originalErr).(*WrappedError)

	stringResult := wrapped.String()
	assert.Contains(t, stringResult, "test error")
	assert.Contains(t, stringResult, "trace_test.go")

	// Should be the same as Error()
	assert.Equal(t, wrapped.Error(), stringResult)
}

func TestWrappedError_Unwrap(t *testing.T) {
	originalErr := errors.New("test error")
	wrapped := Wrap(originalErr).(*WrappedError)

	unwrapped := wrapped.Unwrap()
	assert.Equal(t, originalErr, unwrapped)
}

func TestUnwrap_NilError(t *testing.T) {
	result := Unwrap(nil)
	assert.Nil(t, result)
}

func TestUnwrap_RegularError(t *testing.T) {
	originalErr := errors.New("test error")
	result := Unwrap(originalErr)
	assert.Equal(t, originalErr, result)
}

func TestUnwrap_SingleWrappedError(t *testing.T) {
	originalErr := errors.New("original error")
	wrapped := Wrap(originalErr)

	result := Unwrap(wrapped)
	assert.Equal(t, originalErr, result)
}

func TestUnwrap_MultipleWrappedErrors(t *testing.T) {
	// Create a chain of wrapped errors
	originalErr := errors.New("original error")

	// Manually create nested wrapped errors to test recursive unwrapping
	wrapped1 := &WrappedError{
		Cause:      originalErr,
		StackTrace: []string{"trace1"},
	}
	wrapped2 := &WrappedError{Cause: wrapped1, StackTrace: []string{"trace2"}}
	wrapped3 := &WrappedError{Cause: wrapped2, StackTrace: []string{"trace3"}}

	result := Unwrap(wrapped3)
	assert.Equal(t, originalErr, result)
}

func TestUnwrap_WithStandardLibraryWrapping(t *testing.T) {
	// Test with errors created using standard library wrapping
	originalErr := errors.New("original error")
	wrappedErr1 := errors.New("wrapped: " + originalErr.Error())

	// Create a custom error that implements Unwrap
	customErr := &customWrappedError{
		msg:   "custom wrapper",
		cause: wrappedErr1,
	}

	result := Unwrap(customErr)
	assert.Equal(t, wrappedErr1, result)
}

func TestWrap_StackTraceContent(t *testing.T) {
	originalErr := errors.New("test error")
	wrapped := Wrap(originalErr).(*WrappedError)

	// Check that stack trace has reasonable content
	assert.NotEmpty(t, wrapped.StackTrace)

	// Each entry should have file:line format
	for _, trace := range wrapped.StackTrace {
		assert.Contains(t, trace, ":")
		parts := strings.Split(trace, ":")
		assert.Len(
			t,
			parts,
			2,
			"Stack trace entry should be in file:line format",
		)
	}
}

// Helper type for testing standard library error wrapping
type customWrappedError struct {
	msg   string
	cause error
}

func (e *customWrappedError) Error() string {
	return e.msg
}

func (e *customWrappedError) Unwrap() error {
	return e.cause
}
