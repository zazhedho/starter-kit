package moduleseed

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

var defaultActions = []string{"list", "view", "create", "update", "delete"}

type Definition struct {
	Name        string
	DisplayName string
	Path        string
	Icon        string
	OrderIndex  int
	ParentName  string
	Resource    string
	Actions     []string
	GrantRoles  []string
}

func (d Definition) Normalize() Definition {
	d.Name = strings.TrimSpace(strings.ToLower(d.Name))
	d.DisplayName = strings.TrimSpace(d.DisplayName)
	d.Path = strings.TrimSpace(d.Path)
	d.Icon = strings.TrimSpace(d.Icon)
	d.ParentName = strings.TrimSpace(strings.ToLower(d.ParentName))
	d.Resource = strings.TrimSpace(strings.ToLower(d.Resource))

	if d.Resource == "" {
		d.Resource = d.Name
	}
	if len(d.Actions) == 0 {
		d.Actions = append([]string{}, defaultActions...)
	}

	normalizedActions := make([]string, 0, len(d.Actions))
	for _, action := range d.Actions {
		action = strings.TrimSpace(strings.ToLower(action))
		if action == "" || slices.Contains(normalizedActions, action) {
			continue
		}
		normalizedActions = append(normalizedActions, action)
	}
	d.Actions = normalizedActions

	normalizedRoles := make([]string, 0, len(d.GrantRoles))
	for _, role := range d.GrantRoles {
		role = strings.TrimSpace(strings.ToLower(role))
		if role == "" || slices.Contains(normalizedRoles, role) {
			continue
		}
		normalizedRoles = append(normalizedRoles, role)
	}
	d.GrantRoles = normalizedRoles

	return d
}

func (d Definition) Validate() error {
	if d.Name == "" {
		return errors.New("name is required")
	}
	if d.DisplayName == "" {
		return errors.New("display_name is required")
	}
	if d.Path == "" {
		return errors.New("path is required")
	}
	if d.Resource == "" {
		return errors.New("resource is required")
	}
	if len(d.Actions) == 0 {
		return errors.New("at least one action is required")
	}

	for _, action := range d.Actions {
		if strings.TrimSpace(action) == "" {
			return errors.New("actions must not contain empty values")
		}
	}

	return nil
}

func RenderSQL(input Definition) (string, error) {
	def := input.Normalize()
	if err := def.Validate(); err != nil {
		return "", err
	}

	var sections []string
	sections = append(sections, renderMenuInsert(def))
	sections = append(sections, renderPermissionInsert(def))
	if len(def.GrantRoles) > 0 {
		sections = append(sections, renderRolePermissionInsert(def))
	}

	return strings.Join(sections, "\n\n"), nil
}

func renderMenuInsert(def Definition) string {
	columns := []string{"id", "name", "display_name", "path", "icon", "order_index", "is_active"}
	values := []string{
		"gen_random_uuid()",
		quote(def.Name),
		quote(def.DisplayName),
		quote(def.Path),
		quote(def.Icon),
		fmt.Sprintf("%d", def.OrderIndex),
		"TRUE",
	}

	if def.ParentName != "" {
		columns = []string{"id", "name", "display_name", "path", "icon", "parent_id", "order_index", "is_active"}
		values = []string{
			"gen_random_uuid()",
			quote(def.Name),
			quote(def.DisplayName),
			quote(def.Path),
			quote(def.Icon),
			fmt.Sprintf("(SELECT id FROM menu_items WHERE name = %s AND deleted_at IS NULL LIMIT 1)", quote(def.ParentName)),
			fmt.Sprintf("%d", def.OrderIndex),
			"TRUE",
		}
	}

	return fmt.Sprintf(
		"INSERT INTO menu_items (%s)\nVALUES\n    (%s)\nON CONFLICT (name) DO NOTHING;",
		strings.Join(columns, ", "),
		strings.Join(values, ", "),
	)
}

func renderPermissionInsert(def Definition) string {
	values := make([]string, 0, len(def.Actions))
	for _, action := range def.Actions {
		values = append(values, fmt.Sprintf(
			"    (gen_random_uuid(), %s, %s, %s, %s)",
			quote(permissionName(action, def.Name)),
			quote(permissionDisplayName(action, def.DisplayName)),
			quote(def.Resource),
			quote(action),
		))
	}

	return fmt.Sprintf(
		"INSERT INTO permissions (id, name, display_name, resource, action) VALUES\n%s\nON CONFLICT (name) DO NOTHING;",
		strings.Join(values, ",\n"),
	)
}

func renderRolePermissionInsert(def Definition) string {
	quotedRoles := make([]string, 0, len(def.GrantRoles))
	for _, role := range def.GrantRoles {
		quotedRoles = append(quotedRoles, quote(role))
	}

	return fmt.Sprintf(
		"INSERT INTO role_permissions (role_id, permission_id)\nSELECT r.id, p.id\nFROM roles r\nJOIN permissions p ON p.resource = %s\nWHERE r.name IN (%s)\nON CONFLICT DO NOTHING;",
		quote(def.Resource),
		strings.Join(quotedRoles, ", "),
	)
}

func permissionName(action, moduleName string) string {
	return fmt.Sprintf("%s_%s", strings.ToLower(strings.TrimSpace(action)), strings.ToLower(strings.TrimSpace(moduleName)))
}

func permissionDisplayName(action, displayName string) string {
	return fmt.Sprintf("%s %s", humanize(action), displayName)
}

func humanize(input string) string {
	parts := strings.Fields(strings.ReplaceAll(strings.TrimSpace(input), "_", " "))
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func quote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}
