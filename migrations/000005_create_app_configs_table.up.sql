CREATE TABLE IF NOT EXISTS app_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_key VARCHAR(150) NOT NULL UNIQUE,
    display_name VARCHAR(150) NOT NULL,
    category VARCHAR(100) NOT NULL,
    value TEXT NOT NULL DEFAULT '',
    description TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP,
    deleted_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_app_configs_category ON app_configs(category);
CREATE INDEX IF NOT EXISTS idx_app_configs_is_active ON app_configs(is_active);
CREATE INDEX IF NOT EXISTS idx_app_configs_deleted_at ON app_configs(deleted_at);

INSERT INTO menu_items (id, name, display_name, path, icon, order_index, is_active)
VALUES
    (gen_random_uuid(), 'configs', 'Configurations', '/configs', 'bi-sliders', 903, TRUE)
ON CONFLICT (name) DO NOTHING;

INSERT INTO permissions (id, name, display_name, resource, action) VALUES
    (gen_random_uuid(), 'list_configs', 'List Configurations', 'configs', 'list'),
    (gen_random_uuid(), 'view_configs', 'View Configuration Detail', 'configs', 'view'),
    (gen_random_uuid(), 'update_configs', 'Update Configurations', 'configs', 'update')
ON CONFLICT (name) DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.resource = 'configs'
WHERE r.name IN ('admin', 'superadmin')
ON CONFLICT DO NOTHING;
