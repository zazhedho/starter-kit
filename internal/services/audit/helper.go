package serviceaudit

import (
	"encoding/json"
	"fmt"
	domainaudit "starter-kit/internal/domain/audit"
	"starter-kit/internal/dto"
	"starter-kit/utils"
	"strings"
)

func sanitizePayload(input interface{}) interface{} {
	normalized := utils.NormalizePayload(input)
	return sanitizeValue(normalized)
}

func sanitizeValue(input interface{}) interface{} {
	switch v := input.(type) {
	case map[string]interface{}:
		return sanitizeMap(v)
	case []interface{}:
		return sanitizeSlice(v)
	default:
		return v
	}
}

func sanitizeMap(in map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(in))
	for k, val := range in {
		if isSensitiveKey(k) {
			out[k] = "[REDACTED]"
			continue
		}

		out[k] = sanitizeValue(val)
	}
	return out
}

func sanitizeSlice(values []interface{}) []interface{} {
	out := make([]interface{}, 0, len(values))
	for _, val := range values {
		out = append(out, sanitizeValue(val))
	}
	return out
}

func isSensitiveKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	return strings.Contains(k, "password") ||
		strings.Contains(k, "token") ||
		strings.Contains(k, "secret") ||
		strings.Contains(k, "otp")
}

func humanizeAuditValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return value
	}

	value = strings.ReplaceAll(value, "_", " ")
	value = strings.ReplaceAll(value, "-", " ")
	return strings.Join(strings.Fields(value), " ")
}

func toAuditResponses(items []domainaudit.AuditTrail) []dto.AuditTrailResponse {
	responses := make([]dto.AuditTrailResponse, 0, len(items))
	for _, item := range items {
		responses = append(responses, toAuditResponse(item))
	}
	return responses
}

func toAuditResponse(item domainaudit.AuditTrail) dto.AuditTrailResponse {
	actionLabel := titleAuditValue(item.Action)
	resourceLabel := titleAuditValue(item.Resource)
	statusLabel := titleAuditValue(item.Status)

	return dto.AuditTrailResponse{
		ID:            item.ID,
		OccurredAt:    item.OccurredAt,
		Actor:         dto.AuditActor{UserID: item.ActorUserID, Role: titleAuditValue(item.ActorRole)},
		Action:        item.Action,
		ActionLabel:   actionLabel,
		Resource:      item.Resource,
		ResourceLabel: resourceLabel,
		ResourceID:    item.ResourceID,
		Status:        item.Status,
		StatusLabel:   statusLabel,
		Summary:       buildAuditSummary(statusLabel, item.Message, resourceLabel),
		Message:       item.Message,
		ErrorMessage:  item.ErrorMessage,
		RequestID:     item.RequestID,
		IPAddress:     item.IPAddress,
		UserAgent:     item.UserAgent,
		BeforeData:    decodeAuditJSON(item.BeforeData),
		AfterData:     decodeAuditJSON(item.AfterData),
		Metadata:      decodeAuditJSON(item.Metadata),
		CreatedAt:     item.CreatedAt,
	}
}

func buildAuditSummary(statusLabel, message, resourceLabel string) string {
	message = strings.TrimSpace(message)
	if message != "" {
		return fmt.Sprintf("%s: %s", statusLabel, message)
	}

	resourceLabel = strings.TrimSpace(resourceLabel)
	if resourceLabel == "" {
		return statusLabel
	}
	return fmt.Sprintf("%s: %s", statusLabel, resourceLabel)
}

func decodeAuditJSON(value string) interface{} {
	value = strings.TrimSpace(value)
	if value == "" || value == "null" {
		return nil
	}

	var decoded interface{}
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return value
	}
	return decoded
}

func titleAuditValue(value string) string {
	value = humanizeAuditValue(value)
	if value == "" {
		return value
	}

	words := strings.Fields(value)
	for i, word := range words {
		if word == "" {
			continue
		}
		words[i] = strings.ToUpper(word[:1]) + strings.ToLower(word[1:])
	}
	return strings.Join(words, " ")
}
