# starter-temp

NestJS + Drizzle + Postgres starter with dynamic roles and permission-based
access control. Routes check permission strings, not role names; roles are data
that administrators can create at runtime.

## Quick start

```bash
pnpm install
docker run -d --name starter-temp-db \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=app \
  -p 5434:5432 -v starter_temp_pgdata:/var/lib/postgresql/data \
  --restart unless-stopped postgres:16
pnpm db:migrate
pnpm db:seed
pnpm start:dev
```

Swagger is available at `http://localhost:4000/docs`.

Copy `.env.example` to `.env` and set a strong `JWT_SECRET`. Set
`SEED_OWNER_EMAIL` and `SEED_OWNER_PASSWORD` to create a deterministic first
Owner during seeding. Otherwise, the first registered user becomes Owner.

## Access control

- `src/permissions/permissions.registry.ts` is the app-specific permission registry.
- Permissions use `resource:action`, `resource:*`, or `*`.
- User overrides can grant or deny permissions. Deny always wins, including over wildcards.
- `JwtAuthGuard` and `PermissionsGuard` are global and run in that order.
- Routes are protected by default. Use `@Public()` to opt out.
- Use `@RequirePermission('user:read')` to protect a route.
- Permissions are resolved per request, so changes apply immediately.

## Built-in safety rules

- System roles cannot be deleted or renamed; Owner permissions are locked.
- Actors can grant only permissions they hold themselves.
- Actors can manage only roles and users whose permissions they fully hold.
- Roles assigned to users cannot be deleted.
- The last active Owner cannot be demoted, deactivated, deleted, or denied access.
- Users cannot deactivate or delete themselves.

## Scripts

| Script             | Purpose                                                     |
| ------------------ | ----------------------------------------------------------- |
| `pnpm db:generate` | Generate a migration from schema changes                    |
| `pnpm db:migrate`  | Apply migrations                                            |
| `pnpm db:seed`     | Create the default tenant, system roles, and optional Owner |
| `pnpm test`        | Run unit tests                                              |
| `pnpm test:e2e`    | Run RBAC e2e tests against `app_test`                       |
| `pnpm build`       | Compile the Nest application                                |
| `pnpm lint`        | Run type-aware linting                                      |

## E2E tests

Create an isolated test database and run the suite without touching `app`:

```bash
PGPASSWORD=postgres createdb -h localhost -p 5434 -U postgres app_test
pnpm test:e2e
```

The test database uses `.env.test`, runs migrations automatically, and is
truncated between suite setup runs.

## Adapting this template

1. Add resources and actions to the permission registry.
2. Add feature modules and decorate routes with `@RequirePermission(...)`.
3. Create roles through `POST /roles` or extend the seed script.
4. Keep tenant-owned queries scoped through the tenant stored in CLS.

Tenant IDs are stored in a real `tenants` table. The migration seeds the
`default` tenant before adding foreign keys, so a fresh database is safe to
initialize.
