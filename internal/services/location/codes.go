package location

import (
	"strings"

	domainlocation "starter-kit/internal/domain/location"
)

const maxCodeLength = 20

// Codes reach SQL, cache keys, delete patterns and the Location Service query: nothing else is let through.
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

func validateCode(field, code string) error {
	if !isCode(code) {
		return domainlocation.NewInvalidCode(field)
	}
	return nil
}

// Codes are relative to the parent (code_format=short) unless they already start with it; any other is refused.
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

func childCodeParam(parent, code string) string {
	if parent != "" && strings.HasPrefix(code, parent) && len(code) > len(parent) {
		return code[len(parent):]
	}
	return code
}
