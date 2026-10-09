package filter

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"starter-kit/utils"
)

type BaseParams struct {
	Search         string         `json:"search" form:"search"`
	Filters        map[string]any `json:"filters" form:"filters"`
	OrderBy        string         `json:"order_by" form:"order_by"`
	OrderDirection string         `json:"order_direction" form:"order_direction"`
	Page           int            `json:"page" form:"page"`
	Limit          int            `json:"limit" form:"limit"`
	Offset         int            `json:"offset" form:"offset"`
	Columns        []string       `json:"columns" form:"columns"`
}

func GetBaseParams(query url.Values, defOrderBy, defOrderDirection string, defLimit int) (req BaseParams, err error) {
	req.Search = query.Get("search")
	req.OrderBy = query.Get("order_by")
	req.OrderDirection = query.Get("order_direction")
	req.Columns = query["columns"]
	if req.Page, err = parseQueryInt(query, "page"); err != nil {
		return
	}
	if req.Limit, err = parseQueryInt(query, "limit"); err != nil {
		return
	}

	normalizePagination(&req, defLimit)
	if req.OrderBy == "" {
		req.OrderBy = defOrderBy
	}
	if direction := utils.NormalizeKey(req.OrderDirection); direction != "asc" && direction != "desc" {
		req.OrderDirection = defOrderDirection
	}
	req.Filters = parseFilters(query)
	return
}

func parseQueryInt(query url.Values, key string) (int, error) {
	values, ok := query[key]
	if !ok {
		return 0, nil
	}
	value := ""
	if len(values) > 0 {
		value = values[0]
	}
	return strconv.Atoi(value)
}

func normalizePagination(req *BaseParams, defaultLimit int) {
	if req.Page < 1 {
		req.Page = 1
	}
	if req.Limit == -1 {
		req.Page = 1
		req.Offset = 0
		return
	}
	if req.Limit < 1 || req.Limit > 10000 {
		req.Limit = defaultLimit
	}
	req.Offset = (req.Page - 1) * req.Limit
}

func parseFilters(query url.Values) map[string]any {
	filters := make(map[string]any)
	for key, values := range query {
		if !strings.HasPrefix(key, "filters[") || !strings.HasSuffix(key, "]") {
			continue
		}
		value := ""
		if len(values) > 0 {
			value = values[0]
		}
		filterKey := strings.TrimSuffix(strings.TrimPrefix(key, "filters["), "]")
		var jsonValue any
		if err := json.Unmarshal([]byte(value), &jsonValue); err == nil {
			filters[filterKey] = jsonValue
		} else {
			filters[filterKey] = value
		}
	}
	return filters
}

func whitelistTransform(
	filters map[string]any,
	allowed []string,
	transform func(any) any,
) map[string]any {
	if filters == nil {
		return nil
	}

	allowedSet := make(map[string]struct{}, len(allowed))
	for _, k := range allowed {
		allowedSet[k] = struct{}{}
	}

	out := make(map[string]any, len(allowedSet))
	for k, v := range filters {
		if _, ok := allowedSet[k]; ok {
			if transform != nil {
				out[k] = transform(v)
			} else {
				out[k] = v
			}
		}
	}
	return out
}

func WhitelistFilter(filters map[string]any, allowed []string) map[string]any {
	return whitelistTransform(filters, allowed, nil)
}

func WhitelistStringFilter(filters map[string]any, allowed []string) map[string]any {
	return whitelistTransform(filters, allowed, func(v any) any {
		switch t := v.(type) {
		case nil:
			return ""
		case string:
			return t
		case fmt.Stringer:
			return t.String()
		case []string:
			return strings.Join(t, ",")
		default:
			return fmt.Sprintf("%v", v)
		}
	})
}
