import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import * as argon2 from 'argon2';
import { and, eq, inArray, ne, sql } from 'drizzle-orm';
import { ClsService } from 'nestjs-cls';
import { DRIZZLE } from '../db/db.module.js';
import type { Database } from '../db/db.module.js';
import {
  rolePermissions,
  roles,
  userPermissionOverrides,
  userRoles,
  users,
} from '../db/schema.js';
import { canGrant } from '../permissions/can.js';
import type { EffectivePermissions } from '../permissions/can.js';
import { PermissionsService } from '../permissions/permissions.service.js';
import { OWNER_ROLE } from '../roles/system-roles.js';
import type {
  CreateUserDto,
  SetOverridesDto,
  SetRolesDto,
  UpdateUserDto,
} from './users.schemas.js';

type Tx = Parameters<Parameters<Database['transaction']>[0]>[0];
type Reader = Pick<Database, 'select'>;

const USER_ADMIN_LOCK_ID = 727002;

@Injectable()
export class UsersService {
  constructor(
    @Inject(DRIZZLE) private readonly db: Database,
    private readonly cls: ClsService,
    private readonly permissions: PermissionsService,
  ) {}

  private get tenantId(): string {
    return this.cls.get('tenantId');
  }

  async list() {
    const rows = await this.db
      .select({
        id: users.id,
        email: users.email,
        name: users.name,
        isActive: users.isActive,
        createdAt: users.createdAt,
      })
      .from(users)
      .where(eq(users.tenantId, this.tenantId))
      .orderBy(users.email);
    if (!rows.length) return [];

    const assigned = await this.db
      .select({ userId: userRoles.userId, id: roles.id, name: roles.name })
      .from(userRoles)
      .innerJoin(roles, eq(roles.id, userRoles.roleId))
      .where(inArray(userRoles.userId, rows.map((row) => row.id)));

    return rows.map((user) => ({
      ...user,
      roles: assigned
        .filter((role) => role.userId === user.id)
        .map(({ id, name }) => ({ id, name })),
    }));
  }

  async get(id: string) {
    const user = await this.findUser(this.db, id);
    const [assigned, overrides, effective] = await Promise.all([
      this.db
        .select({ id: roles.id, name: roles.name })
        .from(userRoles)
        .innerJoin(roles, eq(roles.id, userRoles.roleId))
        .where(eq(userRoles.userId, id)),
      this.db
        .select({
          permission: userPermissionOverrides.permission,
          effect: userPermissionOverrides.effect,
        })
        .from(userPermissionOverrides)
        .where(eq(userPermissionOverrides.userId, id)),
      this.permissions.getEffective(id),
    ]);

    return {
      id: user.id,
      email: user.email,
      name: user.name,
      isActive: user.isActive,
      createdAt: user.createdAt,
      roles: assigned,
      overrides,
      effectivePermissions: effective,
    };
  }

  async create(dto: CreateUserDto, actor: EffectivePermissions) {
    const roleIds = [...new Set(dto.roleIds)];

    const id = await this.db.transaction(async (tx) => {
      await this.lock(tx);
      const assignable = await this.loadRoles(tx, roleIds);
      this.assertCanGrantRoles(actor, assignable);

      const [existing] = await tx
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.tenantId, this.tenantId), eq(users.email, dto.email)));
      if (existing) throw new ConflictException('Email already registered');

      const [user] = await tx
        .insert(users)
        .values({
          tenantId: this.tenantId,
          email: dto.email,
          name: dto.name,
          passwordHash: await argon2.hash(dto.password),
        })
        .returning({ id: users.id });

      if (roleIds.length) {
        await tx
          .insert(userRoles)
          .values(roleIds.map((roleId) => ({ userId: user.id, roleId })));
      }
      return user.id;
    });

    return this.get(id);
  }

  async update(
    id: string,
    dto: UpdateUserDto,
    actor: EffectivePermissions,
    actorId: string,
  ) {
    await this.db.transaction(async (tx) => {
      await this.lock(tx);
      const target = await this.findUser(tx, id);
      await this.assertCanManage(actor, id);

      if (dto.isActive === false && target.isActive) {
        if (id === actorId) {
          throw new ForbiddenException('You cannot deactivate yourself');
        }
        if (await this.isActiveOwner(tx, id)) {
          await this.assertNotLastOwner(tx, id);
        }
      }

      const patch: Partial<typeof users.$inferInsert> = {
        updatedAt: new Date(),
      };
      if (dto.name !== undefined) patch.name = dto.name;
      if (dto.isActive !== undefined) patch.isActive = dto.isActive;
      await tx.update(users).set(patch).where(eq(users.id, id));
    });

    return this.get(id);
  }

  async setRoles(id: string, dto: SetRolesDto, actor: EffectivePermissions) {
    const wanted = new Set(dto.roleIds);

    await this.db.transaction(async (tx) => {
      await this.lock(tx);
      const target = await this.findUser(tx, id);
      await this.assertCanManage(actor, id);

      const current = await tx
        .select({ roleId: userRoles.roleId })
        .from(userRoles)
        .where(eq(userRoles.userId, id));
      const currentIds = new Set(current.map((role) => role.roleId));
      const added = [...wanted].filter((roleId) => !currentIds.has(roleId));
      const removed = [...currentIds].filter((roleId) => !wanted.has(roleId));

      const changed = await this.loadRoles(tx, [...added, ...removed]);
      this.assertCanGrantRoles(actor, changed);
      await this.loadRoles(tx, [...wanted]);

      const removingOwner = changed.some(
        (role) => removed.includes(role.id) && role.name === OWNER_ROLE,
      );
      if (removingOwner && target.isActive) {
        await this.assertNotLastOwner(tx, id);
      }

      await tx.delete(userRoles).where(eq(userRoles.userId, id));
      if (wanted.size) {
        await tx
          .insert(userRoles)
          .values([...wanted].map((roleId) => ({ userId: id, roleId })));
      }
    });

    return this.get(id);
  }

  async setOverrides(
    id: string,
    dto: SetOverridesDto,
    actor: EffectivePermissions,
  ) {
    const byPermission = new Map(
      dto.overrides.map((override) => [override.permission, override.effect]),
    );
    const blocked = [...byPermission]
      .filter(([permission, effect]) =>
        effect === 'grant' && !canGrant(actor, permission),
      )
      .map(([permission]) => permission);
    if (blocked.length) {
      throw new ForbiddenException(
        `You cannot grant permissions you don't hold: ${blocked.join(', ')}`,
      );
    }

    await this.db.transaction(async (tx) => {
      await this.lock(tx);
      const target = await this.findUser(tx, id);
      await this.assertCanManage(actor, id);

      const hasDeny = [...byPermission.values()].includes('deny');
      if (hasDeny && target.isActive && (await this.isActiveOwner(tx, id))) {
        await this.assertNotLastOwner(tx, id);
      }

      await tx
        .delete(userPermissionOverrides)
        .where(eq(userPermissionOverrides.userId, id));
      if (byPermission.size) {
        await tx.insert(userPermissionOverrides).values(
          [...byPermission].map(([permission, effect]) => ({
            userId: id,
            permission,
            effect,
          })),
        );
      }
    });

    return this.get(id);
  }

  async remove(id: string, actor: EffectivePermissions, actorId: string) {
    await this.db.transaction(async (tx) => {
      await this.lock(tx);
      const target = await this.findUser(tx, id);
      if (id === actorId) {
        throw new ForbiddenException('You cannot delete yourself');
      }
      await this.assertCanManage(actor, id);
      if (target.isActive && (await this.isActiveOwner(tx, id))) {
        await this.assertNotLastOwner(tx, id);
      }
      await tx.delete(users).where(eq(users.id, id));
    });
  }

  private async lock(tx: Tx) {
    await tx.execute(sql`select pg_advisory_xact_lock(${USER_ADMIN_LOCK_ID})`);
  }

  private async findUser(query: Reader, id: string) {
    const [user] = await query
      .select()
      .from(users)
      .where(and(eq(users.id, id), eq(users.tenantId, this.tenantId)));
    if (!user) throw new NotFoundException('User not found');
    return user;
  }

  private async loadRoles(query: Reader, ids: string[]) {
    const unique = [...new Set(ids)];
    if (!unique.length) return [];

    const rows = await query
      .select({ id: roles.id, name: roles.name })
      .from(roles)
      .where(and(inArray(roles.id, unique), eq(roles.tenantId, this.tenantId)));
    if (rows.length !== unique.length) {
      throw new BadRequestException('Unknown role id');
    }

    const permissions = await query
      .select()
      .from(rolePermissions)
      .where(inArray(rolePermissions.roleId, unique));
    return rows.map((role) => ({
      ...role,
      permissions: permissions
        .filter((permission) => permission.roleId === role.id)
        .map((permission) => permission.permission),
    }));
  }

  private assertCanGrantRoles(
    actor: EffectivePermissions,
    rolesToCheck: { name: string; permissions: string[] }[],
  ) {
    for (const role of rolesToCheck) {
      const blocked = role.permissions.filter(
        (permission) => !canGrant(actor, permission),
      );
      if (blocked.length) {
        throw new ForbiddenException(
          `You cannot assign or remove role "${role.name}": it holds permissions you don't (${blocked.join(', ')})`,
        );
      }
    }
  }

  private async assertCanManage(
    actor: EffectivePermissions,
    targetId: string,
  ) {
    const target = await this.permissions.getEffective(targetId);
    const blocked = target.allow.filter(
      (permission) => !canGrant(actor, permission),
    );
    if (blocked.length) {
      throw new ForbiddenException(
        `You cannot manage a user who holds permissions you don't: ${blocked.join(', ')}`,
      );
    }
  }

  private async isActiveOwner(query: Reader, userId: string) {
    const [row] = await query
      .select({ id: users.id })
      .from(users)
      .innerJoin(userRoles, eq(userRoles.userId, users.id))
      .innerJoin(roles, eq(roles.id, userRoles.roleId))
      .where(
        and(
          eq(users.id, userId),
          eq(users.isActive, true),
          eq(roles.tenantId, this.tenantId),
          eq(roles.name, OWNER_ROLE),
        ),
      );
    return !!row;
  }

  private async assertNotLastOwner(query: Reader, userId: string) {
    const [{ count }] = await query
      .select({ count: sql<number>`count(distinct ${users.id})::int` })
      .from(users)
      .innerJoin(userRoles, eq(userRoles.userId, users.id))
      .innerJoin(roles, eq(roles.id, userRoles.roleId))
      .where(
        and(
          eq(users.isActive, true),
          ne(users.id, userId),
          eq(roles.tenantId, this.tenantId),
          eq(roles.name, OWNER_ROLE),
        ),
      );
    if (count === 0) {
      throw new ConflictException(
        'This would leave the system without an active Owner',
      );
    }
  }
}