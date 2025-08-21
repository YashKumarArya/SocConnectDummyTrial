import { Request, Response, NextFunction } from 'express';

export function validateSchema(schema: any) {
  return (req: Request, res: Response, next: NextFunction) => {
    // run schema validation (zod/class-validator)
    return next();
  };
}
