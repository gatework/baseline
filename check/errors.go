package check

import (
	"errors"
	"fmt"
	"strconv"
)

// ErrParam reports a parameter value a check cannot use.
var ErrParam = errors.New("check: invalid parameter")

func errOffset(s string) error { return fmt.Errorf("%w: offset %q is not +HH:MM", ErrParam, s) }

func itoa(n int) string { return strconv.Itoa(n) }
