# Postman collection

One file, `starter-kit.postman_collection.json`: import it once. Requests are grouped in top-level folders
(Health, Auth, Users, Roles, Permissions, Menus, Configurations, Audit Trails, Sessions, Media, Locations);
the Media and Locations folders belong to the example modules, so delete them with the module.

Collection variables to set (Collection > Variables):

| Variable | Set to |
|---|---|
| `base_url` | the service, `http://localhost:8080` by default |
| `access_token`, `refresh_token` | from the Login response; requests send `access_token` as the bearer token |
| `user_id`, `role_id`, `permission_id`, `menu_id`, `config_id`, `audit_id`, `session_id` | ids taken from list responses, used by the "by ID" requests |
| `media_id`, `location_sync_job_id` | from the upload and sync responses |
| `impersonation_token`, `reset_token`, `google_id_token` | only for the impersonation, password-reset and Google login requests |

The Media requests need `MEDIA_ENABLED=true`, and the Sessions requests need Redis. The routes themselves are
documented in [`docs/modules/`](../modules/) and pinned by each module's `routes_test.go`.
