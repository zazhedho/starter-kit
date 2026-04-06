package servicemenu

import (
	"errors"
	domainmenu "starter-kit/internal/domain/menu"
	"starter-kit/internal/dto"
	interfacemenu "starter-kit/internal/interfaces/menu"
	interfacepermission "starter-kit/internal/interfaces/permission"
	serviceshared "starter-kit/internal/services/shared"
	"starter-kit/pkg/filter"
	"starter-kit/utils"
	"time"
)

type MenuService struct {
	MenuRepo       interfacemenu.RepoMenuInterface
	PermissionRepo interfacepermission.RepoPermissionInterface
}

func NewMenuService(menuRepo interfacemenu.RepoMenuInterface, permissionRepo interfacepermission.RepoPermissionInterface) *MenuService {
	return &MenuService{
		MenuRepo:       menuRepo,
		PermissionRepo: permissionRepo,
	}
}

func (s *MenuService) Create(req dto.MenuCreate) (domainmenu.MenuItem, error) {
	existing, _ := s.MenuRepo.GetByName(req.Name)
	if existing.Id != "" {
		return domainmenu.MenuItem{}, errors.New("menu with this name already exists")
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}

	data := domainmenu.MenuItem{
		Id:          utils.CreateUUID(),
		Name:        req.Name,
		DisplayName: req.DisplayName,
		Path:        req.Path,
		Icon:        req.Icon,
		ParentId:    req.ParentId,
		OrderIndex:  req.OrderIndex,
		IsActive:    isActive,
		CreatedAt:   time.Now(),
	}

	if err := s.MenuRepo.Store(data); err != nil {
		return domainmenu.MenuItem{}, err
	}

	return data, nil
}

func (s *MenuService) GetByID(id string) (domainmenu.MenuItem, error) {
	return s.MenuRepo.GetByID(id)
}

func (s *MenuService) GetAll(params filter.BaseParams) ([]domainmenu.MenuItem, int64, error) {
	return s.MenuRepo.GetAll(params)
}

func (s *MenuService) GetActiveMenus() ([]domainmenu.MenuItem, error) {
	return s.MenuRepo.GetActiveMenus()
}

func (s *MenuService) GetUserMenus(userId string) ([]domainmenu.MenuItem, error) {
	activeMenus, err := s.MenuRepo.GetActiveMenus()
	if err != nil {
		return nil, err
	}

	permissions, err := s.PermissionRepo.GetUserPermissions(userId)
	if err != nil {
		return nil, err
	}

	resources := make([]string, 0, len(permissions))
	for _, permission := range permissions {
		if permission.Resource == "" {
			continue
		}
		resources = append(resources, permission.Resource)
	}

	return serviceshared.ResolveAccessibleMenus(activeMenus, resources), nil
}

func (s *MenuService) Update(id string, req dto.MenuUpdate) (domainmenu.MenuItem, error) {
	menu, err := s.MenuRepo.GetByID(id)
	if err != nil {
		return domainmenu.MenuItem{}, err
	}

	if req.DisplayName != "" {
		menu.DisplayName = req.DisplayName
	}
	if req.Path != "" {
		menu.Path = req.Path
	}
	if req.Icon != "" {
		menu.Icon = req.Icon
	}
	if req.ParentId != nil {
		menu.ParentId = req.ParentId
	}
	if req.OrderIndex != nil {
		menu.OrderIndex = *req.OrderIndex
	}
	if req.IsActive != nil {
		menu.IsActive = *req.IsActive
	}
	menu.UpdatedAt = new(time.Now())

	if err := s.MenuRepo.Update(menu); err != nil {
		return domainmenu.MenuItem{}, err
	}

	return menu, nil
}

func (s *MenuService) Delete(id string) error {
	return s.MenuRepo.Delete(id)
}

var _ interfacemenu.ServiceMenuInterface = (*MenuService)(nil)
