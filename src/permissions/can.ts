export interface EffectivePermissions {
  allow: string[];
  deny: string[];
}

function matches(list: string[], needed: string): boolean {
  if (list.includes('*') || list.includes(needed)) return true;

  const [resource] = needed.split(':');
  return list.includes(`${resource}:*`);
}

// Deny always wins over allow.
export function can(effective: EffectivePermissions, needed: string): boolean {
  if (matches(effective.deny, needed)) return false;
  return matches(effective.allow, needed);
}

// Can this actor hand out permission `permission` to someone else?
export function canGrant(
  effective: EffectivePermissions,
  permission: string,
): boolean {
  if (!can(effective, permission)) return false;

  // A wildcard grant must not include a permission the actor is denied.
  if (permission === '*') return effective.deny.length === 0;
  if (permission.endsWith(':*')) {
    const prefix = permission.slice(0, -1);
    return !effective.deny.some((denied) => denied.startsWith(prefix));
  }

  return true;
}