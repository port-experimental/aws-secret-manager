/**
 * AWS Secrets Manager Self-Service Action
 * Main entry point for the webhook server
 */

const app = require('./server');
const logger = require('./logger');
const PortClient = require('./port-client');

const PORT = process.env.WEBHOOK_PORT || 3000;
const WEBHOOK_PATH = process.env.WEBHOOK_PATH || '/webhook';

/**
 * Validate environment configuration on startup
 */
function validateStartupConfig() {
  const warnings = [];
  const errors = [];

  // Check Port credentials (warnings only, as they might not be needed for all operations)
  if (!process.env.PORT_CLIENT_ID || !process.env.PORT_CLIENT_SECRET) {
    warnings.push('Port credentials (PORT_CLIENT_ID, PORT_CLIENT_SECRET) are missing. Action logs and status updates will fail.');
  }

  // Check AWS credentials (warnings only, as they might use IAM roles or be provided per-action)
  const hasAWSAccessKey = !!process.env.AWS_ACCESS_KEY_ID;
  const hasAWSSecretKey = !!process.env.AWS_SECRET_ACCESS_KEY;
  
  if (hasAWSAccessKey && !hasAWSSecretKey) {
    errors.push('AWS_ACCESS_KEY_ID is set but AWS_SECRET_ACCESS_KEY is missing. Both must be provided together.');
  }
  if (!hasAWSAccessKey && hasAWSSecretKey) {
    errors.push('AWS_SECRET_ACCESS_KEY is set but AWS_ACCESS_KEY_ID is missing. Both must be provided together.');
  }

  if (!hasAWSAccessKey && !hasAWSSecretKey) {
    warnings.push('No AWS credentials found in environment. Will attempt to use default AWS credential chain (IAM roles, ~/.aws/credentials, etc.).');
  }

  // Log warnings
  if (warnings.length > 0) {
    warnings.forEach(warning => logger.warn(`WARNING: ${warning}`));
  }

  // Log errors and exit if critical
  if (errors.length > 0) {
    errors.forEach(error => logger.error(`ERROR: ${error}`));
    logger.error('\nPlease fix the configuration errors above before starting the server.');
    process.exit(1);
  }

  if (warnings.length > 0 || errors.length > 0) {
    logger.info('');
  }
}

// Validate configuration on startup
validateStartupConfig();

const server = app.listen(PORT, () => {
  logger.info('\nAWS Secrets Manager SSA Webhook Server Started');
  logger.info('='.repeat(80));
  logger.info(`Listening on port ${PORT}`);
  logger.info(`Webhook URL: http://localhost:${PORT}${WEBHOOK_PATH}`);
  logger.info(`Health check: http://localhost:${PORT}/health`);
  logger.info(`Status: http://localhost:${PORT}/status`);
  logger.info('='.repeat(80));
  logger.info('\nWaiting for Port action invocations...\n');
});

// Handle server errors
server.on('error', (error) => {
  if (error.code === 'EADDRINUSE') {
    logger.error(`Port ${PORT} is already in use`);
  } else {
    logger.error('Server error:', error);
  }
  process.exit(1);
});

// Graceful shutdown
process.on('SIGINT', () => {
  logger.info('\n\nShutting down webhook server...');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  logger.info('\n\nSIGTERM received, shutting down...');
  server.close(() => {
    logger.info('Server closed');
    process.exit(0);
  });
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  logger.error('Unhandled rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

