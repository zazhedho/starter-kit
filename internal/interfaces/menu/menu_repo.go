package interfacemenu

import (
	domainmenu "starter-kit/internal/domain/menu"
	interfacegeneric "starter-kit/internal/interfaces/generic"
)

type RepoMenuInterface interface {
	interfacegeneric.GenericRepository[domainmenu.MenuItem]

	GetByName(name string) (domainmenu.MenuItem, error)
	GetActiveMenus() ([]domainmenu.MenuItem, error)
	GetUserMenus(userId string) ([]domainmenu.MenuItem, error)
}
