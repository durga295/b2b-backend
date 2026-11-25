import { NextFunction, Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';

export type AuthUser = { id: string; role: string; organizationId?: string };
declare global { namespace Express { interface Request { user?: AuthUser } } }
export function auth(req: Request, res: Response, next: NextFunction) {
  const token = req.headers.authorization?.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });
  try { req.user = jwt.verify(token, env.jwtSecret) as AuthUser; next(); }
  catch { return res.status(401).json({ error: 'Invalid or expired token' }); }
}
export function allow(...allowed: string[]) { return (req: Request, res: Response, next: NextFunction) => req.user && (allowed.includes(req.user.role) || req.user.role === 'admin') ? next() : res.status(403).json({ error: 'You do not have permission to perform this action' }); }
