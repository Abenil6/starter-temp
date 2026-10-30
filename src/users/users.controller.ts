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
  Put,
} from '@nestjs/common';
import { ApiBearerAuth, ApiTags } from '@nestjs/swagger';
import { CurrentUser } from '../auth/current-user.decorator.js';
import type { AuthUser } from '../auth/current-user.decorator.js';
import { ZodValidationPipe } from '../common/zod-validation.pipe.js';
import type { EffectivePermissions } from '../permissions/can.js';
import { CurrentPermissions } from '../permissions/current-permissions.decorator.js';
import { RequirePermission } from '../permissions/require-permission.decorator.js';
import { UsersService } from './users.service.js';
import {
  createUserSchema,
  setOverridesSchema,
  setRolesSchema,
  updateUserSchema,
} from './users.schemas.js';
import type {
  CreateUserDto,
  SetOverridesDto,
  SetRolesDto,
  UpdateUserDto,
} from './users.schemas.js';

@ApiTags('users')
@ApiBearerAuth()
@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @Get()
  @RequirePermission('user:read')
  list() {
    return this.users.list();
  }

  @Get(':id')
  @RequirePermission('user:read')
  get(@Param('id', ParseUUIDPipe) id: string) {
    return this.users.get(id);
  }

  @Post()
  @RequirePermission('user:invite')
  create(
    @Body(new ZodValidationPipe(createUserSchema)) dto: CreateUserDto,
    @CurrentPermissions() actor: EffectivePermissions,
  ) {
    return this.users.create(dto, actor);
  }

  @Patch(':id')
  @RequirePermission('user:update')
  update(
    @Param('id', ParseUUIDPipe) id: string,
    @Body(new ZodValidationPipe(updateUserSchema)) dto: UpdateUserDto,
    @CurrentPermissions() actor: EffectivePermissions,
    @CurrentUser() me: AuthUser,
  ) {
    return this.users.update(id, dto, actor, me.id);
  }

  @Put(':id/roles')
  @RequirePermission('user:update')
  setRoles(
    @Param('id', ParseUUIDPipe) id: string,
    @Body(new ZodValidationPipe(setRolesSchema)) dto: SetRolesDto,
    @CurrentPermissions() actor: EffectivePermissions,
  ) {
    return this.users.setRoles(id, dto, actor);
  }

  @Put(':id/overrides')
  @RequirePermission('user:update')
  setOverrides(
    @Param('id', ParseUUIDPipe) id: string,
    @Body(new ZodValidationPipe(setOverridesSchema)) dto: SetOverridesDto,
    @CurrentPermissions() actor: EffectivePermissions,
  ) {
    return this.users.setOverrides(id, dto, actor);
  }

  @Delete(':id')
  @HttpCode(204)
  @RequirePermission('user:delete')
  async remove(
    @Param('id', ParseUUIDPipe) id: string,
    @CurrentPermissions() actor: EffectivePermissions,
    @CurrentUser() me: AuthUser,
  ) {
    await this.users.remove(id, actor, me.id);
  }
}