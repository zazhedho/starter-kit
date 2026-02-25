package serviceaudit

import (
	"errors"
	domainaudit "starter-kit/internal/domain/audit"
	interfaceaudit "starter-kit/internal/interfaces/audit"
	"starter-kit/utils"
	"strings"
	"time"
)

type AuditService struct {
	AuditRepo interfaceaudit.RepoAuditInterface
}

func NewAuditService(auditRepo interfaceaudit.RepoAuditInterface) *AuditService {
	return &AuditService{
		AuditRepo: auditRepo,
	}
}

func (s *AuditService) Store(req domainaudit.AuditEvent) error {
	if strings.TrimSpace(req.Action) == "" {
		return errors.New("action is required")
	}
	if strings.TrimSpace(req.Resource) == "" {
		return errors.New("resource is required")
	}
	if strings.TrimSpace(req.Status) == "" {
		return errors.New("status is required")
	}

	occurredAt := req.OccurredAt
	if occurredAt.IsZero() {
		occurredAt = time.Now()
	}

	before := sanitizePayload(req.BeforeData)
	after := sanitizePayload(req.AfterData)
	meta := sanitizePayload(req.Metadata)

	data := domainaudit.AuditTrail{
		ID:           utils.CreateUUID(),
		OccurredAt:   occurredAt,
		ActorUserID:  utils.NormalizeUUIDPointer(req.ActorUserID),
		ActorRole:    strings.TrimSpace(req.ActorRole),
		Action:       strings.TrimSpace(req.Action),
		Resource:     strings.TrimSpace(req.Resource),
		ResourceID:   strings.TrimSpace(req.ResourceID),
		Status:       strings.TrimSpace(req.Status),
		Message:      strings.TrimSpace(req.Message),
		ErrorMessage: strings.TrimSpace(req.ErrorMessage),
		RequestID:    strings.TrimSpace(req.RequestID),
		IPAddress:    strings.TrimSpace(req.IPAddress),
		UserAgent:    strings.TrimSpace(req.UserAgent),
		BeforeData:   utils.JsonEncode(before),
		AfterData:    utils.JsonEncode(after),
		Metadata:     utils.JsonEncode(meta),
		CreatedAt:    time.Now(),
	}

	return s.AuditRepo.Store(data)
}

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

var _ interfaceaudit.ServiceAuditInterface = (*AuditService)(nil)
