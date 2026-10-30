import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../auth/public.decorator.js';
import { can } from './can.js';
import type { EffectivePermissions } from './can.js';
import { PermissionsService } from './permissions.service.js';
import { REQUIRED_PERMISSIONS_KEY } from './require-permission.decorator.js';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly permissions: PermissionsService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const targets = [context.getHandler(), context.getClass()];

    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, targets)) {
      return true;
    }

    const required = this.reflector.getAllAndOverride<string[]>(
      REQUIRED_PERMISSIONS_KEY,
      targets,
    );
    if (!required?.length) return true;

    const request = context.switchToHttp().getRequest();
    if (!request.user) throw new UnauthorizedException();

    const effective: EffectivePermissions =
      (request.effectivePermissions ??= await this.permissions.getEffective(
        request.user.id,
      ));

    const missing = required.filter((permission) => !can(effective, permission));
    if (missing.length) {
      throw new ForbiddenException(`Missing permission: ${missing.join(', ')}`);
    }

    return true;
  }
}