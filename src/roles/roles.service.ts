import {
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { and, eq, inArray, sql } from 'drizzle-orm';
import { ClsService } from 'nestjs-cls';
import { DRIZZLE } from '../db/db.module.js';
import type { Database } from '../db/db.module.js';
import { rolePermissions, roles, userRoles } from '../db/schema.js';
import { canGrant } from '../permissions/can.js';
import type { EffectivePermissions } from '../permissions/can.js';
import type { CreateRoleDto, UpdateRoleDto } from './roles.schemas.js';
import { OWNER_ROLE } from './system-roles.js';

type Role = typeof roles.$inferSelect;

@Injectable()
export class RolesService {
  constructor(
    @Inject(DRIZZLE) private readonly db: Database,
    private readonly cls: ClsService,
  ) {}

  private get tenantId(): string {
    return this.cls.get('tenantId');
  }

  async list() {
    const rows = await this.db
      .select()
      .from(roles)
      .where(eq(roles.tenantId, this.tenantId))
      .orderBy(roles.name);
    return this.withDetails(rows);
  }

  async get(id: string) {
    const [row] = await this.db
      .select()
      .from(roles)
      .where(and(eq(roles.id, id), eq(roles.tenantId, this.tenantId)));
    if (!row) throw new NotFoundException('Role not found');

    const [role] = await this.withDetails([row]);
    return role;
  }

  async create(dto: CreateRoleDto, actor: EffectivePermissions) {
    const permissions = [...new Set(dto.permissions)];
    this.assertCanGrantAll(actor, permissions);
    await this.assertNameFree(dto.name);

    const id = await this.db.transaction(async (tx) => {
      const [role] = await tx
        .insert(roles)
        .values({
          tenantId: this.tenantId,
          name: dto.name,
          description: dto.description,
        })
        .returning({ id: roles.id });

      if (permissions.length) {
        await tx
          .insert(rolePermissions)
          .values(permissions.map((permission) => ({ roleId: role.id, permission })));
      }
      return role.id;
    });

    return this.get(id);
  }

  async update(id: string, dto: UpdateRoleDto, actor: EffectivePermissions) {
    const role = await this.get(id);

    if (role.isSystem && dto.name !== undefined && dto.name !== role.name) {
      throw new ForbiddenException('System roles cannot be renamed');
    }
    if (role.name === OWNER_ROLE && dto.permissions) {
      throw new ForbiddenException('Owner permissions cannot be changed');
    }

    this.assertCanGrantAll(actor, role.permissions, 'manage a role that has');
    if (dto.name !== undefined && dto.name !== role.name) {
      await this.assertNameFree(dto.name);
    }

    const permissions = dto.permissions
      ? [...new Set(dto.permissions)]
      : undefined;
    if (permissions) this.assertCanGrantAll(actor, permissions);

    await this.db.transaction(async (tx) => {
      const patch: Partial<typeof roles.$inferInsert> = {};
      if (dto.name !== undefined) patch.name = dto.name;
      if (dto.description !== undefined) patch.description = dto.description;
      if (Object.keys(patch).length) {
        await tx.update(roles).set(patch).where(eq(roles.id, id));
      }
      if (permissions) {
        await tx.delete(rolePermissions).where(eq(rolePermissions.roleId, id));
        if (permissions.length) {
          await tx
            .insert(rolePermissions)
            .values(permissions.map((permission) => ({ roleId: id, permission })));
        }
      }
    });

    return this.get(id);
  }

  async remove(id: string, actor: EffectivePermissions) {
    const role = await this.get(id);
    if (role.isSystem) {
      throw new ForbiddenException('System roles cannot be deleted');
    }

    this.assertCanGrantAll(actor, role.permissions, 'manage a role that has');
    if (role.userCount > 0) {
      throw new ConflictException(
        `Role is assigned to ${role.userCount} user(s); reassign them first`,
      );
    }

    await this.db.delete(roles).where(eq(roles.id, id));
  }

  private assertCanGrantAll(
    actor: EffectivePermissions,
    permissions: string[],
    verb = 'grant',
  ) {
    const blocked = permissions.filter(
      (permission) => !canGrant(actor, permission),
    );
    if (blocked.length) {
      throw new ForbiddenException(
        `You cannot ${verb} permissions you don't hold: ${blocked.join(', ')}`,
      );
    }
  }

  private async assertNameFree(name: string) {
    const [existing] = await this.db
      .select({ id: roles.id })
      .from(roles)
      .where(and(eq(roles.tenantId, this.tenantId), eq(roles.name, name)));
    if (existing) {
      throw new ConflictException('A role with this name already exists');
    }
  }

  private async withDetails(rows: Role[]) {
    if (!rows.length) return [];

    const ids = rows.map((role) => role.id);
    const [permissions, counts] = await Promise.all([
      this.db
        .select()
        .from(rolePermissions)
        .where(inArray(rolePermissions.roleId, ids)),
      this.db
        .select({
          roleId: userRoles.roleId,
          count: sql<number>`count(*)::int`,
        })
        .from(userRoles)
        .where(inArray(userRoles.roleId, ids))
        .groupBy(userRoles.roleId),
    ]);

    return rows.map((role) => ({
      ...role,
      permissions: permissions
        .filter((permission) => permission.roleId === role.id)
        .map((permission) => permission.permission)
        .sort(),
      userCount: counts.find((count) => count.roleId === role.id)?.count ?? 0,
    }));
  }
}