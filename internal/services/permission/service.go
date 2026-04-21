package servicepermission

import (
	"context"
	"errors"
	domainpermission "starter-kit/internal/domain/permission"
	"starter-kit/internal/dto"
	interfacepermission "starter-kit/internal/interfaces/permission"
	"starter-kit/pkg/filter"
	"starter-kit/utils"
	"time"
)

type PermissionService struct {
	PermissionRepo interfacepermission.RepoPermissionInterface
}

func NewPermissionService(permissionRepo interfacepermission.RepoPermissionInterface) *PermissionService {
	return &PermissionService{
		PermissionRepo: permissionRepo,
	}
}

func (s *PermissionService) Create(ctx context.Context, req dto.PermissionCreate) (domainpermission.Permission, error) {
	existing, _ := s.PermissionRepo.GetByName(ctx, req.Name)
	if existing.Id != "" {
		return domainpermission.Permission{}, errors.New("permission with this name already exists")
	}

	data := domainpermission.Permission{
		Id:          utils.CreateUUID(),
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Description: req.Description,
		Resource:    req.Resource,
		Action:      req.Action,
		CreatedAt:   time.Now(),
	}

	if err := s.PermissionRepo.Store(ctx, data); err != nil {
		return domainpermission.Permission{}, err
	}

	return data, nil
}

func (s *PermissionService) GetByID(ctx context.Context, id string) (domainpermission.Permission, error) {
	return s.PermissionRepo.GetByID(ctx, id)
}

func (s *PermissionService) GetAll(ctx context.Context, params filter.BaseParams) ([]domainpermission.Permission, int64, error) {
	return s.PermissionRepo.GetAll(ctx, params)
}

func (s *PermissionService) GetByResource(ctx context.Context, resource string) ([]domainpermission.Permission, error) {
	return s.PermissionRepo.GetByResource(ctx, resource)
}

func (s *PermissionService) GetUserPermissions(ctx context.Context, userId string) ([]domainpermission.Permission, error) {
	return s.PermissionRepo.GetUserPermissions(ctx, userId)
}

func (s *PermissionService) Update(ctx context.Context, id string, req dto.PermissionUpdate) (domainpermission.Permission, error) {
	permission, err := s.PermissionRepo.GetByID(ctx, id)
	if err != nil {
		return domainpermission.Permission{}, err
	}

	if req.DisplayName != "" {
		permission.DisplayName = req.DisplayName
	}
	permission.Description = req.Description
	if req.Resource != "" {
		permission.Resource = req.Resource
	}
	if req.Action != "" {
		permission.Action = req.Action
	}
	permission.UpdatedAt = new(time.Now())

	if err := s.PermissionRepo.Update(ctx, permission); err != nil {
		return domainpermission.Permission{}, err
	}

	return permission, nil
}

func (s *PermissionService) Delete(ctx context.Context, id string) error {
	return s.PermissionRepo.Delete(ctx, id)
}

var _ interfacepermission.ServicePermissionInterface = (*PermissionService)(nil)
