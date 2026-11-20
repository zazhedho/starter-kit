package location

import (
	"strings"

	domainlocation "starter-kit/internal/domain/location"
)

// maxCodeLength is the width of the code columns.
const maxCodeLength = 20

// isCode reports whether s is 1 to 20 ASCII digits, the only shape a location
// code takes. Codes reach SQL, cache keys (and their delete patterns) and the
// Location Service query, so nothing else is let through.
func isCode(s string) bool {
	if s == "" || len(s) > maxCodeLength {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validateCode returns a domainlocation.ErrInvalidCode error naming field when
// code is not a location code.
func validateCode(field, code string) error {
	if !isCode(code) {
		return domainlocation.NewInvalidCode(field)
	}
	return nil
}

// childCode turns a code from the Location Service into the stored code of a
// child of parent (empty for provinces). The service answers with codes relative
// to the parent (code_format=short); a code that already starts with the
// parent's is a full code. A code longer than the parent's that does not start
// with it belongs to another parent and is refused, as is anything that is not a
// valid code.
func childCode(parent, raw string) (string, bool) {
	if !isCode(raw) {
		return "", false
	}
	if parent == "" {
		return raw, true
	}
	if strings.HasPrefix(raw, parent) && len(raw) > len(parent) {
		return raw, true
	}
	if len(raw) > len(parent) {
		return "", false
	}
	full := parent + raw
	if !isCode(full) {
		return "", false
	}
	return full, true
}

// childCodeParam is the relative form of code under parent, as the Location
// Service takes it in code_format=short queries.
func childCodeParam(parent, code string) string {
	if parent != "" && strings.HasPrefix(code, parent) && len(code) > len(parent) {
		return code[len(parent):]
	}
	return code
}
