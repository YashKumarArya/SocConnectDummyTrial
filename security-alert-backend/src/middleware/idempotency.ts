import { Request, Response, NextFunction } from 'express';

const seen = new Set<string>();

export function idempotencyMiddleware(req: Request, res: Response, next: NextFunction) {
  const key = (req.header('x-idempotency-key') || (req.body && req.body.event_id) || (req.body && req.body.alert_id)) as string | undefined;
  if (!key) return next();

  if (seen.has(key)) {
    return res.status(409).json({ error: 'Duplicate request' });
  }

  seen.add(key);
  // keep keys for the lifetime of the process in this stub
  return next();
}
