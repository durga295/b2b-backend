import express from 'express';
import cors from 'cors';
import { env } from './config/env';
import routes from './routes';
import { errors, notFound } from './middleware/errors';

const app = express();
app.use(cors({ origin: env.clientOrigin }));
app.use(express.json({ limit: '1mb' }));
app.use('/api/v1', routes);
app.use(notFound);
app.use(errors);
export default app;
