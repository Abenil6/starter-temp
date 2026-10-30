import { z } from 'zod';
import { isValidPermission } from '../permissions/permissions.registry.js';

const name = z.string().trim().min(2).max(50);
const description = z.string().trim().max(255).nullable();
const permission = z
  .string()
  .refine(isValidPermission, { message: 'Unknown permission' });

export const createRoleSchema = z.object({
  name,
  description: description.optional(),
  permissions: z.array(permission).default([]),
});
export type CreateRoleDto = z.infer<typeof createRoleSchema>;

export const updateRoleSchema = z.object({
  name: name.optional(),
  description: description.optional(),
  permissions: z.array(permission).optional(),
});
export type UpdateRoleDto = z.infer<typeof updateRoleSchema>;