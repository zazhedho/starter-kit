package interfacemenu

import (
	domainmenu "starter-kit/internal/domain/menu"
	interfacebase "starter-kit/internal/interfaces/base"
)

type RepoMenuInterface interface {
	interfacebase.GenericRepository[domainmenu.MenuItem]

	GetByName(name string) (domainmenu.MenuItem, error)
	GetActiveMenus() ([]domainmenu.MenuItem, error)
	GetUserMenus(userId string) ([]domainmenu.MenuItem, error)
}
