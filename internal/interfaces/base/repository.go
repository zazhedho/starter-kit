package interfacebase

import "starter-kit/pkg/filter"

type GenericRepository[T any] interface {
	Store(data T) error
	GetByID(id string) (T, error)
	GetAll(params filter.BaseParams) ([]T, int64, error)
	Update(data T) error
	Delete(id string) error
}
