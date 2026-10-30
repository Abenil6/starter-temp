import { can, canGrant } from './can.js';

describe('can()', () => {
  it('allows an exact permission', () => {
    expect(can({ allow: ['user:read'], deny: [] }, 'user:read')).toBe(true);
  });

  it('denies when nothing matches', () => {
    expect(can({ allow: ['user:read'], deny: [] }, 'user:delete')).toBe(false);
  });

  it('supports resource wildcard', () => {
    expect(can({ allow: ['user:*'], deny: [] }, 'user:delete')).toBe(true);
    expect(can({ allow: ['user:*'], deny: [] }, 'role:read')).toBe(false);
  });

  it('supports global wildcard', () => {
    expect(can({ allow: ['*'], deny: [] }, 'anything:goes')).toBe(true);
  });

  it('deny beats allow, even through wildcards', () => {
    const effective = { allow: ['user:*'], deny: ['user:delete'] };
    expect(can(effective, 'user:read')).toBe(true);
    expect(can(effective, 'user:delete')).toBe(false);
    expect(can({ allow: ['*'], deny: ['role:*'] }, 'role:create')).toBe(false);
  });
});

describe('canGrant()', () => {
  it('requires holding the permission', () => {
    expect(canGrant({ allow: ['user:read'], deny: [] }, 'user:read')).toBe(true);
    expect(canGrant({ allow: ['user:read'], deny: [] }, 'user:delete')).toBe(false);
  });

  it('allows anything for an unrestricted Owner', () => {
    expect(canGrant({ allow: ['*'], deny: [] }, '*')).toBe(true);
  });

  it('blocks wildcard grants that would include a denied permission', () => {
    const effective = { allow: ['*'], deny: ['user:delete'] };
    expect(canGrant(effective, 'user:read')).toBe(true);
    expect(canGrant(effective, 'user:*')).toBe(false);
    expect(canGrant(effective, '*')).toBe(false);
  });
});