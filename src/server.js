const express = require('express');
const AWSSecretsService = require('./aws-secrets-service');
const PortClient = require('./port-client');
const logger = require('./logger');
require('dotenv').config();

const app = express();

app.use(express.json());

const portClient = new PortClient();

/**
 * Main webhook endpoint - receives action invocations from Port
 */
app.post(process.env.WEBHOOK_PATH || '/webhook', async (req, res) => {
  const startTime = Date.now();
  
  try {
    const payload = req.body;
    
    // Try to extract runId from standard Port format or custom format
    let runId, action, properties, entity;
    
    // Standard Port webhook format
    if (payload && payload.context && payload.context.runId && payload.action) {
      runId = payload.context.runId;
      action = payload.action;
      properties = payload.properties || {};
      entity = payload.entity;
    } 
    // Custom format - try to extract from headers or custom body structure
    else if (payload) {
      // Check for runId in headers (if configured in Port action)
      runId = req.headers['run_id'] || req.headers['run-id'] || req.headers['RUN_ID'];
      
      // Check for runId in custom body structure
      if (!runId && payload.port_context && payload.port_context.runId) {
        runId = payload.port_context.runId;
      }
      if (!runId && payload.context && payload.context.runId) {
        runId = payload.context.runId;
      }
      if (!runId && payload.runId) {
        runId = payload.runId;
      }
      
      // Extract properties from payload (could be at root level or in properties)
      properties = payload.properties || payload;
      
      // Create minimal action object if missing
      action = payload.action || { identifier: 'create_aws_secret' };
      
      entity = payload.entity;
      
      // If we still don't have runId, log warning but try to continue
      if (!runId) {
        logger.warn('Could not extract runId from payload or headers');
        logger.warn('Payload structure:', JSON.stringify(payload, null, 2));
        logger.warn('Headers:', JSON.stringify(req.headers, null, 2));
      }
    }
    
    // Final validation
    if (!payload || !runId) {
      logger.warn('Invalid webhook payload received:');
      logger.warn('Payload structure:', JSON.stringify(payload, null, 2));
      logger.warn('Headers:', JSON.stringify(req.headers, null, 2));
      return res.status(400).json({
        error: 'Invalid payload',
        message: 'Missing required field: runId (expected in context.runId, headers, or payload)',
        received: payload ? Object.keys(payload) : 'no payload'
      });
    }

    logger.info('\n' + '='.repeat(80));
    logger.info('Port Action Webhook Received');
    logger.info('='.repeat(80));
    logger.info(`Run ID: ${runId}`);
    logger.info(`Action: ${action.identifier || 'unknown'}`);
    logger.info(`User: ${payload.context?.by?.email || payload.context?.by?.user || 'N/A'}`);
    logger.info(`Properties: ${JSON.stringify(properties, null, 2)}`);

    // Process action synchronously and return result
    // For synchronized actions, Port expects the result in the response
    try {
      const result = await processActionSynchronously(runId, action, properties, entity);
      
      // Return success response (for synchronized actions, this determines success/failure)
      res.status(200).json({
        status: 'SUCCESS',
        message: 'Action completed successfully',
        runId: runId,
        result: result,
        timestamp: new Date().toISOString()
      });
    } catch (error) {
      logger.error(`Error processing action ${runId}:`, error);
      
      // Return failure response (for synchronized actions, this marks it as failed)
      res.status(200).json({
        status: 'FAILURE',
        message: error.message || 'Action failed',
        runId: runId,
        error: error.message,
        timestamp: new Date().toISOString()
      });
    }

  } catch (error) {
    logger.error('Webhook endpoint error:', error);
    // Return failure response for synchronized actions
    res.status(200).json({
      status: 'FAILURE',
      message: error.message || 'Error processing action',
      error: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Helper to safely call Port API methods (won't fail for synchronized actions)
 */
async function safePortCall(fn, errorMessage) {
  try {
    return await fn();
  } catch (error) {
    // Extract error message from response data or error message
    const errorMsg = error.response?.data?.message || error.response?.data?.error || error.message || String(error);
    const errorStr = typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg);
    
    // For synchronized actions, Port API calls will fail - that's expected
    // Check for common synchronized action error patterns
    const isSynchronizedError = 
      error.response?.status === 422 ||
      errorStr.includes('synchronized') ||
      errorStr.includes('already finished') ||
      errorStr.includes('Cannot manually change status');
    
    if (isSynchronizedError) {
      // These are expected for synchronized actions, so log at debug level
      logger.debug(`${errorMessage} (action is synchronized): ${errorStr}`);
    } else {
      // Other errors should be logged as warnings
      logger.warn(`${errorMessage}: ${errorStr}`);
    }
    return null;
  }
}

/**
 * Process the action synchronously and return result
 * This is used for synchronized actions where Port expects the result in the response
 */
async function processActionSynchronously(runId, action, properties, entity) {
  // Try to add logs, but don't fail if action is synchronized
  await safePortCall(
    () => portClient.addActionRunLog(runId, `Started processing action: ${action.identifier}`),
    'Could not add action log'
  );

  // Handle AWS Secrets Manager operation
  const result = await handleAWSSecrets(runId, action, properties, entity);

  // Try to add success log, but don't fail if action is synchronized
  await safePortCall(
    () => portClient.addActionRunLog(runId, `Action completed successfully`, 'SUCCESS', 'Completed'),
    'Could not add success log'
  );

  return result;
}

/**
 * Validate required configuration before processing
 */
function validateConfiguration(properties) {
  const errors = [];

  // Validate AWS credentials
  const hasAWSAccessKey = properties.awsAccessKeyId || process.env.AWS_ACCESS_KEY_ID;
  const hasAWSSecretKey = properties.awsSecretAccessKey || process.env.AWS_SECRET_ACCESS_KEY;
  
  // Check if both AWS credentials are provided (or neither, to use default chain)
  if ((hasAWSAccessKey && !hasAWSSecretKey) || (!hasAWSAccessKey && hasAWSSecretKey)) {
    errors.push('AWS credentials must be provided together: both AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or neither (to use default credential chain)');
  }

  // Validate Port credentials (only if we need to make API calls)
  if (!process.env.PORT_CLIENT_ID || !process.env.PORT_CLIENT_SECRET) {
    logger.warn('Port credentials (PORT_CLIENT_ID, PORT_CLIENT_SECRET) are missing. Action logs and status updates may fail.');
  }

  if (errors.length > 0) {
    throw new Error(`Configuration validation failed:\n${errors.join('\n')}`);
  }
}

/**
 * Handle AWS Secrets Manager operations
 */
async function handleAWSSecrets(runId, action, properties, entity) {
  await safePortCall(
    () => portClient.addActionRunLog(runId, 'Starting AWS Secrets Manager operation...'),
    'Could not add log'
  );

  // Validate configuration before proceeding
  validateConfiguration(properties);

  // Initialize AWS Secrets Service
  let secretsService;
  try {
    secretsService = new AWSSecretsService({
      region: properties.region || process.env.AWS_REGION,
      accessKeyId: properties.awsAccessKeyId || process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: properties.awsSecretAccessKey || process.env.AWS_SECRET_ACCESS_KEY,
      sessionToken: properties.awsSessionToken || process.env.AWS_SESSION_TOKEN,
    });
  } catch (error) {
    throw new Error(`AWS configuration error: ${error.message}`);
  }

  const secretName = properties.secretName || properties.secret_name || properties.secret_key;
  if (!secretName) {
    throw new Error('secretName is required (expected secretName, secret_name, or secret_key)');
  }

  const secretValue = properties.secretValue || properties.secret_value;
  if (!secretValue) {
    throw new Error('secretValue is required (expected secretValue or secret_value)');
  }

  // Parse secret value if it's a JSON string
  let parsedValue = secretValue;
  if (typeof secretValue === 'string' && secretValue.trim().startsWith('{')) {
    try {
      parsedValue = JSON.parse(secretValue);
    } catch (e) {
      // Keep as string if parsing fails
    }
  }

  try {
    let result;
    const operation = properties.operation || 'upsert'; // create, update, or upsert

    switch (operation.toLowerCase()) {
      case 'create':
        await safePortCall(
          () => portClient.addActionRunLog(runId, `Creating new secret: ${secretName}`),
          'Could not add log'
        );
        result = await secretsService.createSecret(secretName, parsedValue, {
          description: properties.description || `Secret managed via Port`,
          tags: properties.tags ? (Array.isArray(properties.tags) ? properties.tags : JSON.parse(properties.tags)) : [],
        });
        await safePortCall(
          () => portClient.addActionRunLog(runId, `Secret created successfully`),
          'Could not add log'
        );
        break;

      case 'update':
        await safePortCall(
          () => portClient.addActionRunLog(runId, `Updating existing secret: ${secretName}`),
          'Could not add log'
        );
        result = await secretsService.updateSecret(secretName, parsedValue, {
          description: properties.description,
        });
        await safePortCall(
          () => portClient.addActionRunLog(runId, `Secret updated successfully`),
          'Could not add log'
        );
        break;

      case 'upsert':
      default:
        await safePortCall(
          () => portClient.addActionRunLog(runId, `Creating or updating secret: ${secretName}`),
          'Could not add log'
        );
        result = await secretsService.upsertSecret(secretName, parsedValue, {
          description: properties.description || `Secret managed via Port`,
          tags: properties.tags ? (Array.isArray(properties.tags) ? properties.tags : JSON.parse(properties.tags)) : [],
        });
        await safePortCall(
          () => portClient.addActionRunLog(runId, `Secret created/updated successfully`),
          'Could not add log'
        );
        break;
    }

    // Log secret metadata (without exposing the value)
    await safePortCall(
      () => portClient.addActionRunLog(runId, `Secret ARN: ${result.arn}`),
      'Could not add log'
    );
    await safePortCall(
      () => portClient.addActionRunLog(runId, `Secret Version: ${result.versionId}`),
      'Could not add log'
    );

    // Optionally create/update entity in Port
    // Default is false, can be enabled via env var PORT_CREATE_ENTITY=true or properties.createEntity=true
    const shouldCreateEntity = properties.createEntity !== undefined 
      ? properties.createEntity 
      : process.env.PORT_CREATE_ENTITY === 'true';
    
    if (shouldCreateEntity) {
      const blueprintId = properties.blueprintId || process.env.PORT_BLUEPRINT_ID ;
      if (!blueprintId) {
        throw new Error('blueprintId is required (expected blueprintId or PORT_BLUEPRINT_ID)');
      }
      const entityData = {
        identifier: secretName.replace(/[^a-zA-Z0-9-_]/g, '-').toLowerCase(),
        title: secretName,
        properties: {
          secret_name: secretName,
          secret_arn: result.arn,
          secret_version: result.versionId,
          region: secretsService.config.region,
          operation: operation,
          last_updated: new Date().toISOString(),
        },
      };

      await safePortCall(
        async () => {
          await portClient.upsertEntity(blueprintId, entityData, runId);
          await portClient.addActionRunLog(runId, `Entity created/updated in Port blueprint: ${blueprintId}`);
        },
        'Could not create/update entity'
      );
    }

  } catch (error) {
    await safePortCall(
      () => portClient.addActionRunLog(runId, `Operation failed: ${error.message}`),
      'Could not add error log'
    );
    throw error;
  }
}

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'aws-secrets-ssa',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

/**
 * Status endpoint
 */
app.get('/status', (req, res) => {
  res.json({
    service: 'aws-secrets-ssa',
    version: '1.0.0',
    port: process.env.WEBHOOK_PORT || 3000,
    webhookPath: process.env.WEBHOOK_PATH || '/webhook',
    awsRegion: process.env.AWS_REGION || 'us-east-1',
    uptime: process.uptime(),
    timestamp: new Date().toISOString()
  });
});

// Global error handlers
app.use((err, req, res, next) => {
  logger.error('Unhandled error:', err);
  res.status(500).json({
    error: 'Internal server error',
    message: process.env.NODE_ENV === 'production' ? 'An error occurred' : err.message
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found', path: req.path });
});

module.exports = app;

