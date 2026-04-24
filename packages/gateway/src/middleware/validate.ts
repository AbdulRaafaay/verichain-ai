import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

/** Validates req.body against a Zod schema; returns 400 with field errors on failure. */
export const validate = (schema: ZodSchema) =>
    (req: Request, res: Response, next: NextFunction): void => {
        const result = schema.safeParse(req.body);
        if (!result.success) {
            const errors = (result.error as ZodError).errors.map(e => ({
                field: e.path.join('.'),
                message: e.message,
            }));
            res.status(400).json({ error: 'Validation failed', details: errors });
            return;
        }
        req.body = result.data;
        next();
    };

/** Validates req.query against a Zod schema. */
export const validateQuery = (schema: ZodSchema) =>
    (req: Request, res: Response, next: NextFunction): void => {
        const result = schema.safeParse(req.query);
        if (!result.success) {
            const errors = (result.error as ZodError).errors.map(e => ({
                field: e.path.join('.'),
                message: e.message,
            }));
            res.status(400).json({ error: 'Validation failed', details: errors });
            return;
        }
        req.query = result.data as any;
        next();
    };
