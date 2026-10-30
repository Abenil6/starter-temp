import { Inject, Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { DRIZZLE } from '../db/db.module.js';
import type { Database } from '../db/db.module.js';
import {
  rolePermissions,
  userPermissionOverrides,
  userRoles,
} from '../db/schema.js';
import { EffectivePermissions } from './can.js';

@Injectable()
export class PermissionsService {
  constructor(@Inject(DRIZZLE) private readonly db: Database) {}

  async getEffective(userId: string): Promise<EffectivePermissions> {
    const [fromRoles, overrides] = await Promise.all([
      this.db
        .selectDistinct({ permission: rolePermissions.permission })
        .from(userRoles)
        .innerJoin(rolePermissions, eq(rolePermissions.roleId, userRoles.roleId))
        .where(eq(userRoles.userId, userId)),
      this.db
        .select()
        .from(userPermissionOverrides)
        .where(eq(userPermissionOverrides.userId, userId)),
    ]);

    const allow = new Set(fromRoles.map((role) => role.permission));
    const deny = new Set<string>();
    for (const override of overrides) {
      (override.effect === 'grant' ? allow : deny).add(override.permission);
    }

    return { allow: [...allow], deny: [...deny] };
  }
}