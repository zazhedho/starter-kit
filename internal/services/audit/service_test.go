package serviceaudit

import (
	"errors"
	domainaudit "starter-kit/internal/domain/audit"
	"starter-kit/pkg/filter"
	"testing"
)

type auditRepoMock struct {
	stored domainaudit.AuditTrail
	item   domainaudit.AuditTrail
	items  []domainaudit.AuditTrail
	total  int64
	err    error
}

func (m *auditRepoMock) Store(data domainaudit.AuditTrail) error {
	m.stored = data
	return m.err
}

func (m *auditRepoMock) GetByID(id string) (domainaudit.AuditTrail, error) {
	if m.err != nil {
		return domainaudit.AuditTrail{}, m.err
	}
	return m.item, nil
}

func (m *auditRepoMock) GetAll(params filter.BaseParams) ([]domainaudit.AuditTrail, int64, error) {
	if m.err != nil {
		return nil, 0, m.err
	}
	return append([]domainaudit.AuditTrail{}, m.items...), m.total, nil
}

func (m *auditRepoMock) Update(data domainaudit.AuditTrail) error { return nil }
func (m *auditRepoMock) Delete(id string) error                   { return nil }

func TestGetAllDelegatesToRepository(t *testing.T) {
	repo := &auditRepoMock{
		items: []domainaudit.AuditTrail{
			{ID: "audit-1", Action: "create", Resource: "users", Status: domainaudit.StatusSuccess},
		},
		total: 1,
	}
	service := NewAuditService(repo)

	items, total, err := service.GetAll(filter.BaseParams{Page: 1, Limit: 10})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if total != 1 {
		t.Fatalf("expected total 1, got %d", total)
	}
	if len(items) != 1 || items[0].ID != "audit-1" {
		t.Fatalf("unexpected items: %+v", items)
	}
}

func TestGetByIDDelegatesToRepository(t *testing.T) {
	repo := &auditRepoMock{
		item: domainaudit.AuditTrail{ID: "audit-1", Action: "login", Resource: "auth", Status: domainaudit.StatusSuccess},
	}
	service := NewAuditService(repo)

	item, err := service.GetByID("audit-1")
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if item.ID != "audit-1" {
		t.Fatalf("expected audit-1, got %s", item.ID)
	}
}

func TestGetByIDReturnsRepositoryError(t *testing.T) {
	service := NewAuditService(&auditRepoMock{err: errors.New("not found")})

	_, err := service.GetByID("missing")
	if err == nil || err.Error() != "not found" {
		t.Fatalf("expected not found error, got %v", err)
	}
}
