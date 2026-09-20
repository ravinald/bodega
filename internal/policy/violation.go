package policy

import "fmt"

// ViolationError is returned when a candidate URL or package name fails the
// allow-list for its registry type. Callers in HTTP handlers translate it to
// 403; CLI callers surface the message verbatim.
type ViolationError struct {
	RegistryType string
	Candidate    string
}

func (e *ViolationError) Error() string {
	return fmt.Sprintf("upstream policy: %s source %q is not in the allow-list", e.RegistryType, e.Candidate)
}

// IsViolation reports whether err is a *ViolationError (or wraps one).
func IsViolation(err error) bool {
	if err == nil {
		return false
	}
	var v *ViolationError
	return errorsAs(err, &v)
}

// errorsAs is a lightweight local wrapper to avoid importing errors in every
// file that needs the check; it mirrors errors.As semantics.
func errorsAs(err error, target **ViolationError) bool {
	for {
		if ve, ok := err.(*ViolationError); ok {
			*target = ve
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
		if err == nil {
			return false
		}
	}
}
