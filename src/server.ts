import mongoose from 'mongoose';
import app from './app';
import { env } from './config/env';

mongoose.connect(env.mongoUri).then(() => {
  app.listen(env.port, () => console.log(`API listening at http://localhost:${env.port}`));
}).catch((error) => { console.error('MongoDB connection failed:', error.message); process.exit(1); });
