DELETE FROM role_permissions
WHERE permission_id IN (
    SELECT id FROM permissions WHERE resource = 'media'
);

DELETE FROM permissions WHERE resource = 'media';

DROP TABLE IF EXISTS media;
