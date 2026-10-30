import { Module } from '@nestjs/common';
import { createObserveModule } from '@nestjs/observe';
import { ConfigModule } from '@nestjs/config';
import { APP_GUARD } from '@nestjs/core';
import { ClsModule } from 'nestjs-cls';
import { AuthModule } from './auth/auth.module.js';
import { validateEnv } from './config/env.js';
import { DbModule } from './db/db.module.js';
import { PermissionsModule } from './permissions/permissions.module.js';
import { PermissionsGuard } from './permissions/permissions.guard.js';
import { JwtAuthGuard } from './auth/jwt-auth.guard.js';
import { RolesModule } from './roles/roles.module.js';
import { UsersModule } from './users/users.module.js';

export const { ObserveModule, ObserveInstrument } = createObserveModule();

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true, validate: validateEnv }),
    ClsModule.forRoot({ global: true, middleware: { mount: true } }),
    DbModule,
    PermissionsModule,
    AuthModule,
    RolesModule,
    UsersModule,
  ],
  controllers: [],
  providers: [
    { provide: APP_GUARD, useClass: JwtAuthGuard },
    { provide: APP_GUARD, useClass: PermissionsGuard },
  ],
})
export class AppModule {}
