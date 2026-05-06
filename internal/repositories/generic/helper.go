package repositorygeneric

import (
	"fmt"
	"reflect"
	"starter-kit/pkg/filter"
	"strings"

	"gorm.io/gorm"
)

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
