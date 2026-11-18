# Migrations

This project's own schema changes. The core tables (users, RBAC, audit trails,
app configs) come from authkit and use its own version table; they are not here.

## Naming

```
<UTC YYYYMMDDHHMMSS>_<module>_<change>.up.sql
<UTC YYYYMMDDHHMMSS>_<module>_<change>.down.sql
```

- `<module>` is the feature module (`location`, `media`), lowercase letters and digits.
- `<change>` says what the migration does, lowercase with underscores (`create_tables`, `add_status_column`).
- Every file matches `^\d{14}_[a-z0-9]+_[a-z0-9_]+\.(up|down)\.sql$`.
  `TestMigrationsAreWellFormed` in `internal/architecture` enforces this, that every up has a down
  (and the reverse), and that no two migrations share a version.

## Generate the timestamp

```sh
date -u +%Y%m%d%H%M%S
```

Run it when you create the migration, not when you start the branch.

## Rules

- One change per migration pair. Do not mix two modules or two unrelated changes in one file.
- Never edit a migration that has been applied anywhere (a shared database, CI, another
  developer's machine). Add a new migration that changes the result instead.
- Rebase rule: if a migration from another branch with a later timestamp was merged before
  yours, rename yours (both the up and the down file) to a newer timestamp before merging.
  A migration older than the database's current version is skipped by golang-migrate.
