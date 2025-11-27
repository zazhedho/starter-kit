package interfaceauth

import domainauth "team-leader-development-program/internal/domain/auth"

type RepoAuthInterface interface {
	Store(m domainauth.Blacklist) error
	GetByToken(token string) (domainauth.Blacklist, error)
}
