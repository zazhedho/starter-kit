CREATE TABLE IF NOT EXISTS media (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_user_id UUID NOT NULL,
    object_key TEXT NOT NULL UNIQUE,
    url TEXT NOT NULL,
    original_name TEXT NOT NULL,
    content_type VARCHAR(150) NOT NULL,
    size BIGINT NOT NULL CHECK (size > 0),
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    deleted_at TIMESTAMP,
    CONSTRAINT fk_media_owner
        FOREIGN KEY (owner_user_id) REFERENCES users(id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_media_deleted_at ON media(deleted_at);
CREATE INDEX IF NOT EXISTS idx_media_owner_created_at ON media(owner_user_id, created_at DESC, id DESC);

-- Acting on your own files needs no permission; the _any actions cover everyone's.
INSERT INTO permissions (id, name, display_name, resource, action)
SELECT gen_random_uuid(), v.name, v.display_name, 'media', v.action
FROM (VALUES
    ('list_any_media', 'List Any Media', 'list_any'),
    ('delete_any_media', 'Delete Any Media', 'delete_any')
) AS v(name, display_name, action)
ON CONFLICT (name) WHERE deleted_at IS NULL DO NOTHING;

INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id
FROM roles r
JOIN permissions p ON p.resource = 'media' AND p.action IN ('list_any', 'delete_any')
WHERE r.name IN ('admin', 'superadmin')
ON CONFLICT DO NOTHING;
