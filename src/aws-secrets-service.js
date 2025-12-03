require('dotenv').config();
const { SecretsManagerClient, CreateSecretCommand, UpdateSecretCommand, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
const logger = require('./logger');

/**
 * AWS Secrets Manager Service
 * Handles creation and updates of AWS secrets
 */
class AWSSecretsService {
  constructor(config = {}) {
    this.config = {
      region: config.region || process.env.AWS_REGION || 'us-east-1',
      accessKeyId: config.accessKeyId || process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: config.secretAccessKey || process.env.AWS_SECRET_ACCESS_KEY,
      sessionToken: config.sessionToken || process.env.AWS_SESSION_TOKEN,
    };

    // Validate AWS configuration
    this._validateConfig();

    // Initialize AWS Secrets Manager client
    const clientConfig = {
      region: this.config.region,
    };

    // Add credentials if provided (otherwise uses default AWS credential chain)
    if (this.config.accessKeyId && this.config.secretAccessKey) {
      clientConfig.credentials = {
        accessKeyId: this.config.accessKeyId,
        secretAccessKey: this.config.secretAccessKey,
      };
      // Add session token if present (required for temporary credentials like ASIA keys)
      if (this.config.sessionToken) {
        clientConfig.credentials.sessionToken = this.config.sessionToken;
      }
    }

    this.client = new SecretsManagerClient(clientConfig);
  }

  /**
   * Format AWS errors with helpful messages
   */
  _formatAWSError(error, operation) {
    const errorMessage = error.message || String(error);
    const errorCode = error.name || error.$metadata?.httpStatusCode;
    
    // Check for credential/authentication errors
    if (errorMessage.includes('security token') || 
        errorMessage.includes('invalid') && errorMessage.includes('token') ||
        errorMessage.includes('InvalidClientTokenId') ||
        errorMessage.includes('SignatureDoesNotMatch') ||
        errorCode === 403) {
      const isTemporaryCredential = this.config?.accessKeyId && this.config.accessKeyId.startsWith('ASIA');
      const sessionTokenNote = isTemporaryCredential && !this.config?.sessionToken 
        ? ' Note: Temporary credentials (ASIA prefix) require AWS_SESSION_TOKEN to be set.' 
        : '';
      return `AWS credentials are invalid or expired. Please verify your AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY are correct and have not expired.${sessionTokenNote} Operation: ${operation}`;
    }
    
    // Check for permission errors
    if (errorMessage.includes('AccessDenied') || 
        errorMessage.includes('UnauthorizedOperation') ||
        errorCode === 403) {
      return `AWS credentials do not have permission to ${operation}. Please check your IAM policy. Original error: ${errorMessage}`;
    }
    
    // Check for region errors
    if (errorMessage.includes('region') || errorMessage.includes('Region')) {
      return `AWS region configuration error. Please verify AWS_REGION is set correctly. Original error: ${errorMessage}`;
    }
    
    // Return original error message if no specific pattern matches
    return `Failed to ${operation}. ${errorMessage}`;
  }

  /**
   * Validate AWS configuration
   * Checks if credentials are provided either explicitly or via environment variables
   * Note: If neither is provided, AWS SDK will try default credential chain (IAM roles, etc.)
   */
  _validateConfig() {
    const missingFields = [];

    // Region is always set (has default), but validate it's not empty
    if (!this.config.region || this.config.region.trim() === '') {
      missingFields.push('AWS_REGION');
    }

    // Check if explicit credentials are provided
    const hasExplicitCredentials = this.config.accessKeyId && this.config.secretAccessKey;
    
    // Check if credentials are in environment
    const hasEnvCredentials = process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY;

    // If no explicit or env credentials, we'll rely on default AWS credential chain
    // But warn if neither is available (though it might still work with IAM roles)
    if (!hasExplicitCredentials && !hasEnvCredentials) {
      // Check if we're likely in an AWS environment (EC2, Lambda, etc.)
      const isAWSEnvironment = process.env.AWS_EXECUTION_ENV || 
                               process.env.AWS_LAMBDA_FUNCTION_NAME ||
                               process.env.ECS_CONTAINER_METADATA_URI;
      
      if (!isAWSEnvironment) {
        logger.warn('No explicit AWS credentials provided. Will attempt to use default AWS credential chain (IAM roles, ~/.aws/credentials, etc.). If this fails, please provide AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY.');
      }
    } else if (hasExplicitCredentials || hasEnvCredentials) {
      // Validate that both access key and secret are present if one is provided
      if (!this.config.accessKeyId) {
        missingFields.push('AWS_ACCESS_KEY_ID');
      }
      if (!this.config.secretAccessKey) {
        missingFields.push('AWS_SECRET_ACCESS_KEY');
      }
      
      // Check if using temporary credentials (ASIA prefix) without session token
      const isTemporaryCredential = this.config.accessKeyId && this.config.accessKeyId.startsWith('ASIA');
      if (isTemporaryCredential && !this.config.sessionToken) {
        logger.warn('Temporary AWS credentials (ASIA prefix) detected but AWS_SESSION_TOKEN is missing. This may cause authentication failures.');
      }
    }

    if (missingFields.length > 0) {
      throw new Error(
        `Missing required AWS configuration: ${missingFields.join(', ')}. ` +
        `Please provide these via environment variables or action properties.`
      );
    }
  }

  /**
   * Create a new secret in AWS Secrets Manager
   */
  async createSecret(secretName, secretValue, options = {}) {
    try {
      logger.info(`Creating secret: ${secretName}`);

      const secretString = typeof secretValue === 'object' 
        ? JSON.stringify(secretValue) 
        : secretValue;

      const command = new CreateSecretCommand({
        Name: secretName,
        SecretString: secretString,
        Description: options.description || `Secret created via Port self-service action`,
        Tags: options.tags || [],
      });

      const response = await this.client.send(command);
      
      logger.info(`Secret created: ${secretName} (ARN: ${response.ARN})`);
      return {
        arn: response.ARN,
        name: response.Name,
        versionId: response.VersionId,
      };
    } catch (error) {
      if (error.name === 'ResourceExistsException') {
        logger.warn(`Secret ${secretName} already exists. Use updateSecret to modify it.`);
        throw new Error(`Secret '${secretName}' already exists. Use update operation instead.`);
      }
      
      // Provide better error messages for credential issues
      const errorMessage = this._formatAWSError(error, 'create secret');
      logger.error(`Failed to create secret ${secretName}: ${errorMessage}`);
      throw new Error(errorMessage);
    }
  }

  /**
   * Update an existing secret in AWS Secrets Manager
   */
  async updateSecret(secretName, secretValue, options = {}) {
    try {
      logger.info(`Updating secret: ${secretName}`);

      const secretString = typeof secretValue === 'object' 
        ? JSON.stringify(secretValue) 
        : secretValue;

      const command = new UpdateSecretCommand({
        SecretId: secretName,
        SecretString: secretString,
        Description: options.description,
      });

      const response = await this.client.send(command);
      
      logger.info(`Secret updated: ${secretName} (Version: ${response.VersionId})`);
      return {
        arn: response.ARN,
        name: response.Name,
        versionId: response.VersionId,
      };
    } catch (error) {
      if (error.name === 'ResourceNotFoundException') {
        logger.warn(`Secret ${secretName} not found. Use createSecret to create it.`);
        throw new Error(`Secret '${secretName}' not found. Use create operation instead.`);
      }
      
      // Provide better error messages for credential issues
      const errorMessage = this._formatAWSError(error, 'update secret');
      logger.error(`Failed to update secret ${secretName}: ${errorMessage}`);
      throw new Error(errorMessage);
    }
  }

  /**
   * Get secret value from AWS Secrets Manager
   */
  async getSecret(secretName) {
    try {
      logger.info(`Retrieving secret: ${secretName}`);

      const command = new GetSecretValueCommand({
        SecretId: secretName,
      });

      const response = await this.client.send(command);
      
      // Try to parse as JSON, otherwise return as string
      try {
        return JSON.parse(response.SecretString);
      } catch {
        return response.SecretString;
      }
    } catch (error) {
      // Provide better error messages for credential issues
      const errorMessage = this._formatAWSError(error, 'get secret');
      logger.error(`Failed to get secret ${secretName}: ${errorMessage}`);
      throw new Error(errorMessage);
    }
  }

  /**
   * Create or update secret (upsert operation)
   */
  async upsertSecret(secretName, secretValue, options = {}) {
    try {
      // Try to update first
      return await this.updateSecret(secretName, secretValue, options);
    } catch (error) {
      // If secret doesn't exist, create it
      if (error.message.includes('not found')) {
        return await this.createSecret(secretName, secretValue, options);
      }
      throw error;
    }
  }
}

module.exports = AWSSecretsService;

