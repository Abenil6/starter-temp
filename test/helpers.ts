import './load-env.js';
import type { INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import { Pool } from 'pg';
import request from 'supertest';
import { AppModule } from '../src/app.module.js';

export async function resetDb() {
  const pool = new Pool({ connectionString: process.env.DATABASE_URL });
  const database = drizzle(pool);
  await migrate(database, { migrationsFolder: './drizzle' });
  await database.execute(
    sql`truncate table users, roles restart identity cascade`,
  );
  await pool.end();
}

export async function createTestApp(): Promise<INestApplication> {
  const moduleRef = await Test.createTestingModule({
    imports: [AppModule],
  }).compile();
  const app = moduleRef.createNestApplication();
  await app.init();
  return app;
}

export const bearer = (token: string) => ({
  Authorization: `Bearer ${token}`,
});

export async function login(
  app: INestApplication,
  email: string,
  password: string,
) {
  const response = await request(app.getHttpServer())
    .post('/auth/login')
    .send({ email, password });
  return response.body.accessToken as string;
}