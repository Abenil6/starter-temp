import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { ZodValidationPipe } from '../common/zod-validation.pipe.js';
import type { EffectivePermissions } from '../permissions/can.js';
import { CurrentPermissions } from '../permissions/current-permissions.decorator.js';
import { PERMISSIONS } from '../permissions/permissions.registry.js';
import { RequirePermission } from '../permissions/require-permission.decorator.js';
import { RolesService } from './roles.service.js';
import {
  createRoleSchema,
  updateRoleSchema,
} from './roles.schemas.js';
import type { CreateRoleDto, UpdateRoleDto } from './roles.schemas.js';

@ApiTags('roles')
@ApiBearerAuth()
@Controller()
export class RolesController {
  constructor(private readonly roles: RolesService) {}

  @Get('permissions')
  @RequirePermission('role:read')
  listPermissions() {
    return Object.entries(PERMISSIONS).map(([resource, actions]) => ({
      resource,
      actions,
    }));
  }

  @Get('roles')
  @RequirePermission('role:read')
  list() {
    return this.roles.list();
  }

  @Get('roles/:id')
  @RequirePermission('role:read')
  get(@Param('id', ParseUUIDPipe) id: string) {
    return this.roles.get(id);
  }

  @Post('roles')
  @RequirePermission('role:create')
  create(
    @Body(new ZodValidationPipe(createRoleSchema)) dto: CreateRoleDto,
    @CurrentPermissions() actor: EffectivePermissions,
  ) {
    return this.roles.create(dto, actor);
  }

  @Patch('roles/:id')
  @RequirePermission('role:update')
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body(new ZodValidationPipe(updateRoleSchema)) dto: UpdateRoleDto,
    @CurrentPermissions() actor: EffectivePermissions,
  ) {
    return this.roles.update(id, dto, actor);
  }

  @Delete('roles/:id')
  @HttpCode(204)
  @RequirePermission('role:delete')
  async remove(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentPermissions() actor: EffectivePermissions,
  ) {
    await this.roles.remove(id, actor);
  }
}