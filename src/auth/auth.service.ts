import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as argon2 from 'argon2';
import { and, eq, sql } from 'drizzle-orm';
import { DRIZZLE } from '../db/db.module.js';
import type { Database } from '../db/db.module.js';
import {
  DEFAULT_TENANT_ID,
  rolePermissions,
  roles,
  userRoles,
  users,
} from '../db/schema.js';
import { MEMBER_ROLE, OWNER_ROLE } from '../roles/system-roles.js';
import type { LoginDto, RegisterDto } from './auth.schemas.js';

type Tx = Parameters<Parameters<Database['transaction']>[0]>[0];

const BOOTSTRAP_LOCK_ID = 727001;

@Injectable()
export class AuthService {
  constructor(
    @Inject(DRIZZLE) private readonly db: Database,
    private readonly jwt: JwtService,
    private readonly config: ConfigService,
  ) {}

  async register(dto: RegisterDto) {
    const userId = await this.db.transaction(async (tx) => {
      await tx.execute(sql`select pg_advisory_xact_lock(${BOOTSTRAP_LOCK_ID})`);

      const [{ count }] = await tx
        .select({ count: sql<number>`count(*)::int` })
        .from(users);
      const isFirst = count === 0;

      if (!isFirst && !this.config.get<boolean>('ALLOW_PUBLIC_REGISTRATION')) {
        throw new ForbiddenException('Registration is closed');
      }

      const [existing] = await tx
        .select({ id: users.id })
        .from(users)
        .where(
          and(eq(users.tenantId, DEFAULT_TENANT_ID), eq(users.email, dto.email)),
        );
      if (existing) throw new ConflictException('Email already registered');

      const [user] = await tx
        .insert(users)
        .values({
          email: dto.email,
          name: dto.name,
          passwordHash: await argon2.hash(dto.password),
        })
        .returning({ id: users.id });

      const role = isFirst
        ? await this.ensureSystemRole(tx, OWNER_ROLE, 'Full access', ['*'])
        : await this.ensureSystemRole(
            tx,
            MEMBER_ROLE,
            'Default role, no permissions',
            [],
          );

      await tx.insert(userRoles).values({ userId: user.id, roleId: role.id });
      return user.id;
    });

    return this.issueToken(userId);
  }

  async login(dto: LoginDto) {
    const [user] = await this.db
      .select()
      .from(users)
      .where(
        and(eq(users.tenantId, DEFAULT_TENANT_ID), eq(users.email, dto.email)),
      );

    const valid = user && (await argon2.verify(user.passwordHash, dto.password));
    if (!valid || !user.isActive) {
      throw new UnauthorizedException('Invalid credentials');
    }

    return this.issueToken(user.id);
  }

  private async issueToken(userId: string) {
    return { accessToken: await this.jwt.signAsync({ sub: userId }) };
  }

  private async ensureSystemRole(
    tx: Tx,
    name: string,
    description: string,
    permissions: string[],
  ) {
    await tx
      .insert(roles)
      .values({ name, description, isSystem: true })
      .onConflictDoNothing({ target: [roles.tenantId, roles.name] });

    const [role] = await tx
      .select()
      .from(roles)
      .where(and(eq(roles.tenantId, DEFAULT_TENANT_ID), eq(roles.name, name)));

    if (permissions.length) {
      await tx
        .insert(rolePermissions)
        .values(permissions.map((permission) => ({ roleId: role.id, permission })))
        .onConflictDoNothing();
    }
    return role;
  }
}