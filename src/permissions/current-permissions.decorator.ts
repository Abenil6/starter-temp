import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { EffectivePermissions } from './can.js';

export const CurrentPermissions = createParamDecorator(
  (_: unknown, context: ExecutionContext): EffectivePermissions =>
    context.switchToHttp().getRequest().effectivePermissions,
);