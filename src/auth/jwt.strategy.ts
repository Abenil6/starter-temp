import { Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { eq } from 'drizzle-orm';
import { ClsService } from 'nestjs-cls';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { DRIZZLE } from '../db/db.module.js';
import type { Database } from '../db/db.module.js';
import { users } from '../db/schema.js';
import { AuthUser } from './current-user.decorator.js';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    config: ConfigService,
    @Inject(DRIZZLE) private readonly db: Database,
    private readonly cls: ClsService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.getOrThrow<string>('JWT_SECRET'),
      ignoreExpiration: false,
    });
  }

  async validate(payload: { sub: string }): Promise<AuthUser> {
    const [user] = await this.db
      .select({
        id: users.id,
        email: users.email,
        tenantId: users.tenantId,
        isActive: users.isActive,
      })
      .from(users)
      .where(eq(users.id, payload.sub));

    if (!user || !user.isActive) throw new UnauthorizedException();

    this.cls.set('tenantId', user.tenantId);
    return { id: user.id, email: user.email, tenantId: user.tenantId };
  }
}