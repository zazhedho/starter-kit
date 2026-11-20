# starter-kit

Go service TEMPLATE (gin + GORM/Postgres) that every new project copies. It is built on `github.com/zazhedho/{authkit,gokit,logus}`. Treat it as a project starting from zero: no legacy or adoption code.

## Working rules (owner decisions)
- **Never read `.env` files.** Use fake values in throwaway shells or containers. Run anything that loads config from a `git archive` copy, which has no `.env`.
- **Git and pull requests.**
  - Branch from an up-to-date `main` and open a PR; `main` is protected and nothing is pushed to it directly.
  - Use Conventional Commits with no attribution lines.
  - Stage files by path; `git add -A`, `--all` and `.` are not allowed.
  - Never use `git stash`.
- **Merge only when every CI check is green, including `zero-issues`:**
  - **SonarCloud must have 0 open issues and 0 hotspots to review**, on the PR and on `main`.
  - Fix issues for real. Use `// NOSONAR <rule> <reason>` only for a proven false positive.
- **Dependencies.**
  - Keep them on the latest versions: `go get -u ./... && go mod tidy`.
  - Write the Go version as the minor line only: `go 1.27` with no toolchain line, and `golang:1.27-alpine` for Docker. Move to the next minor when it ships.
- **Comments.**
  - Write none unless one is truly needed: a security reason, a library or protocol quirk, or an ordering or concurrency rule the code cannot show.
  - Keep each one to 1–2 lines.
  - Do not write doc comments that restate the declaration, narrative comments or section dividers. Prefer clearer names or a small function.
- **README.** It must stand alone: no history, no "upgrading from" sections, no "see another project's README". Migration notes go in the GitHub Release.
- **Process.**
  - Use TDD for behaviour changes: write the failing test first.
  - Run an independent review, with a security review when auth, input or infrastructure is touched, before merging.
  - Batch changes so each repo gets one release, not a string of small ones.

## Template rules
- **Layout and rules:** see the README and `docs/adding-a-module.md`. The worked example there must match the reference modules (`location`, `media`) and must compile.
- **Code layout.**
  - Modules use `internal/{domain,dto,services,repositories}/<module>`, `internal/handlers/http/<module>` (handler plus `ports.go`), `internal/router/<module>/{wire.go,register.go}` and `internal/config/<module>.go`.
  - `internal/router/modules.go` lists the mounted modules.
  - Domain packages use `entity.go` and `errors.go`.
  - Handlers map errors through one `<module>ErrorResponse` and a `fail` helper over `internal/handlers/http/shared`, logging 4xx at WARN and 5xx at ERROR.
- **Architecture guards** live in `internal/architecture`: imports, aliases, package names, constructors, fatal calls, panic, comment length (at most 2 lines) and restating comments.
- **Ownership.** Acting on one's own data needs no permission. Acting on others' data needs `<resource>:<action>_any`, checked with `Auth()` + `LoadPermissions()` + `ScopeFrom(ctx).Has(...)`. A forbidden row answers 404.
- **Migrations.**
  - Names follow `migrations/<UTC YYYYMMDDHHMMSS>_<module>_<change>.{up,down}.sql`. While unreleased, change the existing files instead of adding new ones.
  - Seed permissions with `ON CONFLICT (name) WHERE deleted_at IS NULL`.
- **Config.**
  - Read only through `gokit.GetEnv`, with errors from `gokit.EnvErrors()`.
  - Environment variables win over remote config.
  - Placeholder secrets fail startup outside development.
- **Network.**
  - No proxy is trusted by default; deployments behind a proxy set `TRUSTED_PROXIES`.
  - CORS is open (`*`).
  - The default `LOCATION_SERVICE_BASE_URL` is the owner's maintained service.
- **Docs.** `.env.example`, `docs/modules/*.md` and the single Postman collection (`docs/postman/starter-kit.postman_collection.json`, checked with `jq empty`) must match the code.
- **Tests and checks.**
  - Postgres tests run when `STARTER_KIT_TEST_DATABASE_URL` is set; CI runs them.
  - Before a release, also run `go run ./cmd/api -migrate-only` against an empty database and `docker build .`, both from a `git archive` copy that has no `.env`.
- **Gate:** `go build ./... && go vet ./... && go test -race -count=1 ./... && make lint` (0 issues), and `gofmt -l .` empty.
