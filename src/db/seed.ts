import 'dotenv/config';
import * as argon2 from 'argon2';
import { and, eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { MEMBER_ROLE, OWNER_ROLE } from '../roles/system-roles.js';
import { DEFAULT_TENANT_ID, rolePermissions, roles, tenants, userRoles, users } from './schema.js';
import * as schema from './schema.js';

const db = drizzle;
type SeedDatabase = ReturnType<typeof db<typeof schema>>;

async function ensureRole(
  database: SeedDatabase,
  name: string,
  description: string,
  permissions: string[],
) {
  await database
    .insert(roles)
    .values({ name, description, isSystem: true })
    .onConflictDoNothing({ target: [roles.tenantId, roles.name] });

  const [role] = await database
    .select()
    .from(roles)
    .where(and(eq(roles.tenantId, DEFAULT_TENANT_ID), eq(roles.name, name)));

  if (permissions.length) {
    await database
      .insert(rolePermissions)
      .values(permissions.map((permission) => ({ roleId: role.id, permission })))
      .onConflictDoNothing();
  }
  return role;
}

async function main() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const database = drizzle(pool, { schema });

  await database
    .insert(tenants)
    .values({ id: DEFAULT_TENANT_ID, name: 'Default' })
    .onConflictDoNothing();

  const owner = await ensureRole(database, OWNER_ROLE, 'Full access', ['*']);
  await ensureRole(database, MEMBER_ROLE, 'Default role, no permissions', []);
  console.log('System roles ready');

  const email = process.env.SEED_OWNER_EMAIL?.trim().toLowerCase();
  const password = process.env.SEED_OWNER_PASSWORD;
  if (email && password) {
    const [existing] = await database
      .select({ id: users.id })
      .from(users)
      .where(and(eq(users.tenantId, DEFAULT_TENANT_ID), eq(users.email, email)));
    if (existing) {
      console.log(`Owner ${email} already exists, skipping`);
    } else {
      const [user] = await database
        .insert(users)
        .values({
          email,
          name: 'Owner',
          passwordHash: await argon2.hash(password),
        })
        .returning({ id: users.id });
      await database.insert(userRoles).values({ userId: user.id, roleId: owner.id });
      console.log(`Owner ${email} created`);
    }
  } else {
    console.log(
      'SEED_OWNER_EMAIL / SEED_OWNER_PASSWORD not set; first registration becomes Owner',
    );
  }

  await pool.end();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});