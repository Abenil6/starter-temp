import { SetMetadata } from '@nestjs/common';
import type { Permission } from './permissions.registry.js';

export const REQUIRED_PERMISSIONS_KEY = 'requiredPermissions';

/** All listed permissions are required. */
export const RequirePermission = (...permissions: Permission[]) =>
  SetMetadata(REQUIRED_PERMISSIONS_KEY, permissions);