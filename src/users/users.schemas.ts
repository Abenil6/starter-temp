import { z } from 'zod';
import { isValidPermission } from '../permissions/permissions.registry.js';

const name = z.string().trim().min(1).max(100);

export const createUserSchema = z.object({
  email: z.string().email().transform((value) => value.trim().toLowerCase()),
  password: z.string().min(8).max(128),
  name: name.optional(),
  roleIds: z.array(z.string().uuid()).default([]),
});
export type CreateUserDto = z.infer<typeof createUserSchema>;

export const updateUserSchema = z.object({
  name: name.nullable().optional(),
  isActive: z.boolean().optional(),
});
export type UpdateUserDto = z.infer<typeof updateUserSchema>;

export const setRolesSchema = z.object({
  roleIds: z.array(z.string().uuid()),
});
export type SetRolesDto = z.infer<typeof setRolesSchema>;

export const setOverridesSchema = z.object({
  overrides: z.array(
    z.object({
      permission: z
        .string()
        .refine(isValidPermission, { message: 'Unknown permission' }),
      effect: z.enum(['grant', 'deny']),
    }),
  ),
});
export type SetOverridesDto = z.infer<typeof setOverridesSchema>;