package repositorybase

import (
	"fmt"
	"reflect"
	"starter-kit/pkg/filter"
	"strings"

	"gorm.io/gorm"
)

type SearchFunc func(query *gorm.DB, search string) *gorm.DB
type QueryFunc func(query *gorm.DB) *gorm.DB
type FilterSanitizer func(filters map[string]interface{}, allowed []string) map[string]interface{}

type QueryOptions struct {
	BaseQuery           QueryFunc
	Search              SearchFunc
	AllowedFilters      []string
	FilterSanitizer     FilterSanitizer
	AllowedOrderColumns []string
	DefaultOrders       []string
}

type GenericRepository[T any] struct {
	DB *gorm.DB
}

func New[T any](db *gorm.DB) *GenericRepository[T] {
	return &GenericRepository[T]{DB: db}
}

func (r *GenericRepository[T]) Store(m T) error {
	return r.DB.Create(&m).Error
}

func (r *GenericRepository[T]) GetByID(id string) (ret T, err error) {
	err = r.DB.Where("id = ?", id).First(&ret).Error
	if err != nil {
		return zeroValue[T](), err
	}

	return ret, nil
}

func (r *GenericRepository[T]) GetOneByField(field string, value interface{}) (ret T, err error) {
	err = r.DB.Where(fmt.Sprintf("%s = ?", field), value).First(&ret).Error
	if err != nil {
		return zeroValue[T](), err
	}

	return ret, nil
}

func (r *GenericRepository[T]) GetManyByField(field string, value interface{}) (ret []T, err error) {
	err = r.DB.Where(fmt.Sprintf("%s = ?", field), value).Find(&ret).Error
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func (r *GenericRepository[T]) ExistsByField(field string, value interface{}) (exists bool, err error) {
	var count int64
	err = r.DB.Model(new(T)).Where(fmt.Sprintf("%s = ?", field), value).Count(&count).Error
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (r *GenericRepository[T]) ExistsByFields(filters map[string]interface{}) (exists bool, err error) {
	query := r.DB.Model(new(T))
	for key, value := range filters {
		query = query.Where(fmt.Sprintf("%s = ?", key), value)
	}

	var count int64
	err = query.Count(&count).Error
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (r *GenericRepository[T]) GetAll(params filter.BaseParams, opts QueryOptions) (ret []T, totalData int64, err error) {
	query := r.DB.Model(new(T))
	if opts.BaseQuery != nil {
		query = opts.BaseQuery(query)
	}

	if params.Search != "" && opts.Search != nil {
		query = opts.Search(query, params.Search)
	}

	query = applyFilters(query, params.Filters, opts)

	if err = query.Count(&totalData).Error; err != nil {
		return nil, 0, err
	}

	query, err = applyOrdering(query, params, opts)
	if err != nil {
		return nil, 0, err
	}

	if err = query.Offset(params.Offset).Limit(params.Limit).Find(&ret).Error; err != nil {
		return nil, 0, err
	}

	return ret, totalData, nil
}

func (r *GenericRepository[T]) Update(m T) error {
	return r.DB.Save(&m).Error
}

func (r *GenericRepository[T]) Delete(id string) error {
	return r.DB.Where("id = ?", id).Delete(new(T)).Error
}

func BuildSearchFunc(columns ...string) SearchFunc {
	return func(query *gorm.DB, search string) *gorm.DB {
		if len(columns) == 0 {
			return query
		}

		searchPattern := "%" + search + "%"
		parts := make([]string, 0, len(columns))
		args := make([]interface{}, 0, len(columns))

		for _, column := range columns {
			parts = append(parts, fmt.Sprintf("LOWER(%s) LIKE LOWER(?)", column))
			args = append(args, searchPattern)
		}

		return query.Where(strings.Join(parts, " OR "), args...)
	}
}

func applyFilters(query *gorm.DB, filters map[string]interface{}, opts QueryOptions) *gorm.DB {
	if len(opts.AllowedFilters) == 0 {
		return query
	}

	sanitizer := opts.FilterSanitizer
	if sanitizer == nil {
		sanitizer = filter.WhitelistFilter
	}

	safeFilters := sanitizer(filters, opts.AllowedFilters)
	for key, value := range safeFilters {
		query = applyFilter(query, key, value)
	}

	return query
}

func applyFilter(query *gorm.DB, key string, value interface{}) *gorm.DB {
	if value == nil {
		return query
	}

	switch v := value.(type) {
	case string:
		if strings.TrimSpace(v) == "" {
			return query
		}
		return query.Where(fmt.Sprintf("%s = ?", key), v)
	default:
		if isSliceValue(v) {
			return query.Where(fmt.Sprintf("%s IN ?", key), v)
		}
		return query.Where(fmt.Sprintf("%s = ?", key), v)
	}
}

func applyOrdering(query *gorm.DB, params filter.BaseParams, opts QueryOptions) (*gorm.DB, error) {
	if params.OrderBy != "" && params.OrderDirection != "" {
		if !contains(opts.AllowedOrderColumns, params.OrderBy) {
			return nil, fmt.Errorf("invalid orderBy column: %s", params.OrderBy)
		}

		return query.Order(fmt.Sprintf("%s %s", params.OrderBy, params.OrderDirection)), nil
	}

	for _, order := range opts.DefaultOrders {
		query = query.Order(order)
	}

	return query, nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}

	return false
}

func isSliceValue(value interface{}) bool {
	rv := reflect.ValueOf(value)
	if !rv.IsValid() {
		return false
	}

	switch rv.Kind() {
	case reflect.Slice, reflect.Array:
		return rv.Type().Elem().Kind() != reflect.Uint8
	default:
		return false
	}
}

func zeroValue[T any]() T {
	var zero T
	return zero
}
