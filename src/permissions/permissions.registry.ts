export const PERMISSIONS = {
  user: ['read', 'invite', 'update', 'delete'],
  role: ['read', 'create', 'update', 'delete'],
  // Add app resources here.
} as const;

export type Resource = keyof typeof PERMISSIONS;

export type Permission =
  | '*'
  | `${Resource}:*`
  | { [R in Resource]: `${R}:${(typeof PERMISSIONS)[R][number]}` }[Resource];

export const ALL_PERMISSIONS: string[] = Object.entries(PERMISSIONS).flatMap(
  ([resource, actions]) => actions.map((action) => `${resource}:${action}`),
);

// Used by the admin API to reject unknown permission strings.
export function isValidPermission(permission: string): boolean {
  if (permission === '*') return true;

  const parts = permission.split(':');
  if (parts.length !== 2) return false;

  const [resource, action] = parts;
  if (!(resource in PERMISSIONS)) return false;

  return (
    action === '*' ||
    (PERMISSIONS as Record<string, readonly string[]>)[resource].includes(action)
  );
}