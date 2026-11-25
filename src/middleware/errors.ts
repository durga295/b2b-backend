import { ErrorRequestHandler, NextFunction, Request, Response } from 'express';
export const notFound = (_req: Request, res: Response) => res.status(404).json({ error: 'Route not found' });
export const errors: ErrorRequestHandler = (err, _req, res, _next: NextFunction) => {
  if (err?.code === 11000) return res.status(409).json({ error: 'A record with that unique value already exists' });
  if (err?.name === 'ValidationError' || err?.name === 'CastError') return res.status(400).json({ error: err.message });
  if (err?.name === 'MulterError') return res.status(400).json({ error: err.message });
  console.error(err); return res.status(500).json({ error: 'Unexpected server error' });
};
