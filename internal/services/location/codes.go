package location

import "strings"

func normalizeChildCode(parentCode, code string) string {
	trimmedCode := normalizeCodeSegment(code)
	if trimmedCode == "" {
		return ""
	}

	trimmedParent := normalizeCodeSegment(parentCode)
	if trimmedParent == "" {
		return trimmedCode
	}

	if strings.HasPrefix(trimmedCode, trimmedParent) && len(trimmedCode) > len(trimmedParent) {
		return trimmedCode
	}

	return trimmedParent + trimmedCode
}

func childCodeParam(parentCode, code string) string {
	candidates := childCodeCandidates(parentCode, code)
	if len(candidates) == 0 {
		return normalizeCodeSegment(code)
	}
	return candidates[0]
}

func childCodeCandidates(parentCode, code string) []string {
	trimmedCode := normalizeCodeSegment(code)
	if trimmedCode == "" {
		return nil
	}

	candidates := make([]string, 0, 2)
	trimmedParent := normalizeCodeSegment(parentCode)
	if trimmedParent != "" && strings.HasPrefix(trimmedCode, trimmedParent) {
		suffix := strings.TrimPrefix(trimmedCode, trimmedParent)
		if suffix != "" {
			candidates = append(candidates, suffix)
		}
	}

	candidates = append(candidates, trimmedCode)

	unique := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		unique = append(unique, candidate)
	}

	return unique
}

func normalizeCodeSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	var b strings.Builder
	for _, r := range value {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return value
	}
	return b.String()
}
