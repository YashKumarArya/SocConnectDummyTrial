import { Request, Response, NextFunction } from 'express';

export function authMiddleware(req: Request, res: Response, next: NextFunction) {
  // TODO: mTLS / JWT + RBAC
  return next();
}
