import type { INestApplication } from '@nestjs/common';
import request from 'supertest';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { bearer, createTestApp, login, resetDb } from './helpers.js';

describe('RBAC (e2e)', () => {
  let app: INestApplication;
  let http: ReturnType<INestApplication['getHttpServer']>;
  let ownerToken = '';
  let ownerId = '';
  let frontDeskRoleId = '';
  let frontId = '';
  let frontToken = '';
  const password = 'password123';

  beforeAll(async () => {
    await resetDb();
    app = await createTestApp();
    http = app.getHttpServer();
  });

  afterAll(async () => {
    if (app) await app.close();
  });

  it('first registered user becomes Owner with *', async () => {
    const registration = await request(http)
      .post('/auth/register')
      .send({ email: 'owner@example.com', password });
    expect(registration.status).toBe(201);
    ownerToken = registration.body.accessToken;

    const me = await request(http)
      .get('/auth/me')
      .set(bearer(ownerToken));
    expect(me.status).toBe(200);
    expect(me.body.permissions.allow).toEqual(['*']);
    ownerId = me.body.user.id;
  });

  it('closes public registration after the first user', async () => {
    const response = await request(http)
      .post('/auth/register')
      .send({ email: 'two@example.com', password });
    expect(response.status).toBe(403);
  });

  it('rejects requests without a token', async () => {
    expect((await request(http).get('/roles')).status).toBe(401);
  });

  it('owner creates a role and a user in it', async () => {
    const role = await request(http)
      .post('/roles')
      .set(bearer(ownerToken))
      .send({ name: 'Front Desk', permissions: ['user:read'] });
    expect(role.status).toBe(201);
    frontDeskRoleId = role.body.id;

    const user = await request(http)
      .post('/users')
      .set(bearer(ownerToken))
      .send({
        email: 'front@example.com',
        password,
        roleIds: [frontDeskRoleId],
      });
    expect(user.status).toBe(201);
    frontId = user.body.id;
    expect(user.body.roles).toHaveLength(1);

    frontToken = await login(app, 'front@example.com', password);
    expect(frontToken).toBeTruthy();
  });

  it('enforces role permissions', async () => {
    expect((await request(http).get('/users').set(bearer(frontToken))).status).toBe(200);
    expect((await request(http).get('/roles').set(bearer(frontToken))).status).toBe(403);
  });

  it('applies grant overrides immediately without a new token', async () => {
    const response = await request(http)
      .put(`/users/${frontId}/overrides`)
      .set(bearer(ownerToken))
      .send({ overrides: [{ permission: 'role:read', effect: 'grant' }] });
    expect(response.status).toBe(200);
    expect((await request(http).get('/roles').set(bearer(frontToken))).status).toBe(200);
  });

  it('deny override beats a wildcard role permission', async () => {
    const role = await request(http)
      .post('/roles')
      .set(bearer(ownerToken))
      .send({ name: 'Ops', permissions: ['user:*'] });
    const user = await request(http)
      .post('/users')
      .set(bearer(ownerToken))
      .send({ email: 'ops@example.com', password, roleIds: [role.body.id] });
    await request(http)
      .put(`/users/${user.body.id}/overrides`)
      .set(bearer(ownerToken))
      .send({ overrides: [{ permission: 'user:delete', effect: 'deny' }] });

    const token = await login(app, 'ops@example.com', password);
    expect((await request(http).get('/users').set(bearer(token))).status).toBe(200);
    expect((await request(http).delete(`/users/${frontId}`).set(bearer(token))).status).toBe(403);
  });

  it('prevents privilege escalation through role creation', async () => {
    await request(http)
      .put(`/users/${frontId}/overrides`)
      .set(bearer(ownerToken))
      .send({
        overrides: [
          { permission: 'role:read', effect: 'grant' },
          { permission: 'role:create', effect: 'grant' },
        ],
      });

    const sneaky = await request(http)
      .post('/roles')
      .set(bearer(frontToken))
      .send({ name: 'Sneaky', permissions: ['*'] });
    expect(sneaky.status).toBe(403);

    const allowed = await request(http)
      .post('/roles')
      .set(bearer(frontToken))
      .send({ name: 'Harmless', permissions: ['user:read'] });
    expect(allowed.status).toBe(201);
  });

  it('cannot delete a role assigned to users', async () => {
    const response = await request(http)
      .delete(`/roles/${frontDeskRoleId}`)
      .set(bearer(ownerToken));
    expect(response.status).toBe(409);
  });

  it('locks system roles', async () => {
    const list = await request(http)
      .get('/roles')
      .set(bearer(ownerToken));
    const owner = list.body.find((role: { name: string }) => role.name === 'Owner');

    expect(
      (
        await request(http)
          .patch(`/roles/${owner.id}`)
          .set(bearer(ownerToken))
          .send({ name: 'Boss' })
      ).status,
    ).toBe(403);
    expect(
      (
        await request(http)
          .patch(`/roles/${owner.id}`)
          .set(bearer(ownerToken))
          .send({ permissions: ['user:read'] })
      ).status,
    ).toBe(403);
    expect((await request(http).delete(`/roles/${owner.id}`).set(bearer(ownerToken))).status).toBe(403);
  });

  it('protects the last active Owner', async () => {
    expect(
      (
        await request(http)
          .put(`/users/${ownerId}/roles`)
          .set(bearer(ownerToken))
          .send({ roleIds: [] })
      ).status,
    ).toBe(409);
    expect(
      (
        await request(http)
          .put(`/users/${ownerId}/overrides`)
          .set(bearer(ownerToken))
          .send({ overrides: [{ permission: 'user:read', effect: 'deny' }] })
      ).status,
    ).toBe(409);
    expect(
      (
        await request(http)
          .patch(`/users/${ownerId}`)
          .set(bearer(ownerToken))
          .send({ isActive: false })
      ).status,
    ).toBe(403);
    expect((await request(http).delete(`/users/${ownerId}`).set(bearer(ownerToken))).status).toBe(403);
  });

  it('lower-privileged users cannot manage an Owner', async () => {
    await request(http)
      .put(`/users/${frontId}/overrides`)
      .set(bearer(ownerToken))
      .send({ overrides: [{ permission: 'user:update', effect: 'grant' }] });

    const response = await request(http)
      .patch(`/users/${ownerId}`)
      .set(bearer(frontToken))
      .send({ name: 'Hacked' });
    expect(response.status).toBe(403);
  });
});