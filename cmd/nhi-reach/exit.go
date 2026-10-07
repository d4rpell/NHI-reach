package main

import (
	"errors"
	"fmt"
)

// exitError carries the process exit code of a failure (spec §4).
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

// exitf builds an error that terminates the process with the given exit code.
func exitf(code int, format string, args ...any) error {
	return &exitError{code: code, msg: fmt.Sprintf(format, args...)}
}

// exitCode maps an error to the exit code of spec §4: 3 for input errors, 1 for
// anything else that is not a typed code.
func exitCode(err error) int {
	var ee *exitError
	if errors.As(err, &ee) {
		return ee.code
	}
	return 1
}
