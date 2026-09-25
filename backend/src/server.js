require('dotenv').config();
const app = require('./app');
const connectDB = require('./config/db');

const requiredEnvVars = [
  'MONGO_URI',
  'JWT_ACCESS_SECRET',
  'JWT_REFRESH_SECRET',
  'CLIENT_URL',
];
const missing = requiredEnvVars.filter((key) => !process.env[key]);
if (missing.length) {
  console.error(`[startup] Missing required env vars: ${missing.join(', ')}`);
  process.exit(1);
}

connectDB().then(() => {
  const PORT = process.env.PORT || 5000;
  app.listen(PORT, () => console.log(`[server] listening on port ${PORT}`));
});

process.on('unhandledRejection', (err) => {
  console.error('[unhandledRejection]', err);
  process.exit(1);
});
