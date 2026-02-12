const express = require('express');
require('dotenv').config();
const db = require('./config/db'); // initialize connection
const swaggerUi = require('swagger-ui-express');
const { swaggerSpec } = require('./docs/swagger');
const { securityHeaders, cors, requireJson, rateLimit } = require('./utils/security');
const { requestId, requestLogger } = require('./utils/requestLogger');
const { validateConfig } = require('./utils/config');

const app = express();

// Middleware
app.disable('x-powered-by');
if (process.env.TRUST_PROXY === 'true') {
  app.set('trust proxy', 1);
}
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));
app.use(securityHeaders);
app.use(cors());
app.use(requireJson);
app.use(requestId);
app.use(requestLogger);

// Basic rate limiting
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX) || 120,
}));

// Routes
app.use('/auth', require('./routes/authRoutes'));
app.use('/foods', require('./routes/foodRoutes'));
app.use('/cart', require('./routes/cartRoutes'));
app.use('/orders', require('./routes/orderRoutes'));
app.use('/admin', require('./routes/adminRoutes'));

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

const PORT = process.env.PORT || 3000;
validateConfig();
const server = app.listen(PORT, () => {
  console.log(` Server running on port ${PORT} in ${process.env.NODE_ENV} mode`);
});

const shutdown = async (signal) => {
  console.log(`Received ${signal}. Shutting down...`);
  server.close(async () => {
    try {
      await db.end();
      process.exit(0);
    } catch (err) {
      console.error('Error during shutdown:', err.message);
      process.exit(1);
    }
  });
};

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

module.exports = app;
