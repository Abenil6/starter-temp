import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../auth/public.decorator.js';
import { PermissionsGuard } from './permissions.guard.js';
import { REQUIRED_PERMISSIONS_KEY } from './require-permission.decorator.js';
import type { PermissionsService } from './permissions.service.js';

function contextFor(request: Record<string, unknown>): ExecutionContext {
  const handler = {};
  const controller = {};
  return {
    getHandler: () => handler,
    getClass: () => controller,
    switchToHttp: () => ({ getRequest: () => request }),
  } as ExecutionContext;
}

function guardFor(
  request: Record<string, unknown>,
  required: string[] | undefined,
  effective = { allow: [], deny: [] },
  isPublic = false,
) {
  const reflector = {
    getAllAndOverride: (key: string) =>
      key === IS_PUBLIC_KEY
        ? isPublic
        : key === REQUIRED_PERMISSIONS_KEY
          ? required
          : undefined,
  } as unknown as Reflector;
  const getEffective = vi.fn().mockResolvedValue(effective);
  const permissions = {
    getEffective,
  } as unknown as PermissionsService;

  return {
    guard: new PermissionsGuard(reflector, permissions),
    getEffective,
    context: contextFor(request),
  };
}

describe('PermissionsGuard', () => {
  it('skips public routes without requiring a user', async () => {
    const { guard, context } = guardFor({}, ['user:read'], undefined, true);

    await expect(guard.canActivate(context)).resolves.toBe(true);
  });

  it('allows authenticated-only routes without loading permissions', async () => {
    const { guard, getEffective, context } = guardFor(
      { user: { id: 'user-1' } },
      [],
    );

    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(getEffective).not.toHaveBeenCalled();
  });

  it('requires a user before checking required permissions', async () => {
    const { guard, context } = guardFor({}, ['user:read']);

    await expect(guard.canActivate(context)).rejects.toThrow('Unauthorized');
  });

  it('requires every declared permission and caches the result on the request', async () => {
    const request = { user: { id: 'user-1' } };
    const { guard, getEffective, context } = guardFor(
      request,
      ['user:read', 'user:update'],
      { allow: ['user:*'], deny: [] },
    );

    await expect(guard.canActivate(context)).resolves.toBe(true);
    await expect(guard.canActivate(context)).resolves.toBe(true);
    expect(getEffective).toHaveBeenCalledTimes(1);
    expect(request.effectivePermissions).toEqual({ allow: ['user:*'], deny: [] });
  });

  it('rejects missing permissions and honors deny overrides', async () => {
    const { guard, context } = guardFor(
      { user: { id: 'user-1' } },
      ['user:delete'],
      { allow: ['*'], deny: ['user:delete'] },
    );

    await expect(guard.canActivate(context)).rejects.toThrow(
      'Missing permission: user:delete',
    );
  });
});