const express = require('express');
require('dotenv').config();
const db = require('./config/db'); // initialize connection
const swaggerUi = require('swagger-ui-express');
const { swaggerSpec } = require('./docs/swagger');
const { securityHeaders, cors, requireJson, rateLimit } = require('./utils/security');
const { requestId, requestLogger } = require('./utils/requestLogger');
const { validateConfig } = require('./utils/config');
const { ensureSeedAdmin } = require('./utils/adminSeed');
const { ensureDatabaseAndTables } = require('./utils/dbBootstrap');

const app = express();

// Middleware
app.disable('x-powered-by');
if (process.env.TRUST_PROXY === 'true') {
  app.set('trust proxy', 1);
}
app.use(express.json({
  limit: '100kb',
  verify: (req, res, buf) => {
    req.rawBody = buf.toString('utf8');
  },
}));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(securityHeaders);
app.use(cors());
app.use(requireJson);
app.use(requestId);
app.use(requestLogger);

// Basic rate limiting
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX),
}));

// Routes
app.use('/auth', require('./routes/authRoutes'));
app.use('/foods', require('./routes/foodRoutes'));
app.use('/cart', require('./routes/cartRoutes'));
app.use('/orders', require('./routes/orderRoutes'));
app.use('/admin', require('./routes/adminRoutes'));
app.use('/payments', require('./routes/paymentRoutes'));

// Swagger docs
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, { explorer: true }));
app.get('/api-docs.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(swaggerSpec);
});

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Readiness check
app.get('/ready', async (req, res) => {
  try {
    await db.query('SELECT 1');
    res.json({ status: 'READY', timestamp: new Date().toISOString() });
  } catch (err) {
    res.status(503).json({ status: 'NOT_READY' });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  if (process.env.NODE_ENV === 'production') {
    return res.status(500).json({ error: 'Internal server error' });
  }
  return res.status(500).json({ error: err.message || 'Internal server error' });
});

const PORT = Number(process.env.PORT);
validateConfig();
let server;
const startServer = async () => {
  await ensureDatabaseAndTables();
  const connection = await db.getConnection();
  connection.release();
  console.log('Database ready');
  await ensureSeedAdmin();
  server = app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
  });
};

startServer().catch((err) => {
  console.error('Failed to start server:', err.message);
  process.exit(1);
});

const shutdown = async (signal) => {
  console.log(`Received ${signal}. Shutting down...`);
  if (!server) {
    process.exit(0);
    return;
  }
  server.close(async () => {
    try {
      await db.end();
      process.exit(0);
    } catch (err) {
      console.error('Error during shutdown:', err.message);
      process.exit(1);
    }
  });

  setTimeout(() => {
    console.error('Forced shutdown due to timeout');
    process.exit(1);
  }, 10_000).unref();
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled promise rejection:', reason);
  shutdown('UNHANDLED_REJECTION');
});
process.on('uncaughtException', (err) => {
  console.error('Uncaught exception:', err);
  shutdown('UNCAUGHT_EXCEPTION');
});

module.exports = app;
