package interfacelocation

import domainlocation "starter-kit/internal/domain/location"

type ServiceLocationInterface interface {
	GetProvince(year string) ([]domainlocation.Location, error)
	GetCity(year, lvl, pro string) ([]domainlocation.Location, error)
	GetDistrict(year, lvl, pro, kab string) ([]domainlocation.Location, error)
	GetVillage(year, lvl, pro, kab, kec string) ([]domainlocation.Location, error)
}
