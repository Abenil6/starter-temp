import { Body, Controller, Get, Post } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiBody,
  ApiCreatedResponse,
  ApiOkResponse,
  ApiOperation,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { ZodValidationPipe } from '../common/zod-validation.pipe.js';
import { PermissionsService } from '../permissions/permissions.service.js';
import { AuthService } from './auth.service.js';
import { loginSchema, registerSchema } from './auth.schemas.js';
import type { LoginDto, RegisterDto } from './auth.schemas.js';
import { CurrentUser } from './current-user.decorator.js';
import type { AuthUser } from './current-user.decorator.js';
import { Public } from './public.decorator.js';

@Controller('auth')
@ApiTags('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly permissions: PermissionsService,
  ) {}

  @Public()
  @Post('register')
  @ApiOperation({ summary: 'Register a user' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['email', 'password'],
      properties: {
        email: { type: 'string', format: 'email', example: 'owner@example.com' },
        password: { type: 'string', format: 'password', minLength: 8, maxLength: 128 },
        name: { type: 'string', minLength: 1, maxLength: 100, example: 'Owner' },
      },
    },
  })
  @ApiCreatedResponse({
    description: 'JWT access token',
    schema: { type: 'object', properties: { accessToken: { type: 'string' } } },
  })
  register(@Body(new ZodValidationPipe(registerSchema)) dto: RegisterDto) {
    return this.auth.register(dto);
  }

  @Public()
  @Post('login')
  @ApiOperation({ summary: 'Log in with email and password' })
  @ApiBody({
    schema: {
      type: 'object',
      required: ['email', 'password'],
      properties: {
        email: { type: 'string', format: 'email', example: 'owner@example.com' },
        password: { type: 'string', format: 'password', minLength: 1, maxLength: 128 },
      },
    },
  })
  @ApiCreatedResponse({
    description: 'JWT access token',
    schema: { type: 'object', properties: { accessToken: { type: 'string' } } },
  })
  @ApiUnauthorizedResponse({ description: 'Invalid credentials' })
  login(@Body(new ZodValidationPipe(loginSchema)) dto: LoginDto) {
    return this.auth.login(dto);
  }

  @Get('me')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get the current user and effective permissions' })
  @ApiOkResponse({
    schema: {
      type: 'object',
      properties: {
        user: {
          type: 'object',
          properties: {
            id: { type: 'string', format: 'uuid' },
            email: { type: 'string', format: 'email' },
            tenantId: { type: 'string' },
          },
        },
        permissions: {
          type: 'object',
          properties: {
            allow: { type: 'array', items: { type: 'string' } },
            deny: { type: 'array', items: { type: 'string' } },
          },
        },
      },
    },
  })
  @ApiUnauthorizedResponse({ description: 'Missing or invalid JWT' })
  async me(@CurrentUser() user: AuthUser) {
    return { user, permissions: await this.permissions.getEffective(user.id) };
  }
}