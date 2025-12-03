/**
 * Port API Client
 * Handles authentication and API calls to Port
 */

const axios = require('axios');
const axiosRetryModule = require('axios-retry');
const axiosRetry = axiosRetryModule.default || axiosRetryModule;
const logger = require('./logger');
require('dotenv').config();

// Configure axios with retry
axiosRetry(axios, {
  retries: 3,
  retryDelay: axiosRetryModule.exponentialDelay,
  retryCondition: (error) => {
    return axiosRetryModule.isNetworkOrIdempotentRequestError(error) || 
           (error.response && error.response.status >= 500);
  },
});

class PortClient {
  constructor(config = {}) {
    this.config = {
      clientId: config.clientId || process.env.PORT_CLIENT_ID,
      clientSecret: config.clientSecret || process.env.PORT_CLIENT_SECRET,
    };

    this.portApiUrl = 'https://api.getport.io/v1';
    this.accessToken = null;
    this.tokenExpiry = null;

    // Validate Port configuration (but don't throw during construction to allow lazy validation)
    this._validateConfig();
  }

  /**
   * Validate Port configuration
   */
  _validateConfig() {
    const missingFields = [];

    if (!this.config.clientId) {
      missingFields.push('PORT_CLIENT_ID');
    }
    if (!this.config.clientSecret) {
      missingFields.push('PORT_CLIENT_SECRET');
    }

    if (missingFields.length > 0) {
      logger.warn(
        `Missing Port configuration: ${missingFields.join(', ')}. ` +
        `Port API calls will fail. Please set these environment variables.`
      );
    }
  }

  /**
   * Check if error is related to synchronized actions (expected behavior)
   */
  _isSynchronizedActionError(error) {
    const errorData = error.response?.data;
    const errorMsg = errorData?.message || errorData?.error || error.message || String(error);
    const errorStr = typeof errorMsg === 'string' ? errorMsg : JSON.stringify(errorMsg);
    
    return (
      error.response?.status === 422 ||
      errorStr.includes('synchronized') ||
      errorStr.includes('already finished') ||
      errorStr.includes('Cannot manually change status')
    );
  }

  /**
   * Get Port API access token
   */
  async getAccessToken() {
    // Return cached token if still valid
    if (this.accessToken && this.tokenExpiry && Date.now() < this.tokenExpiry) {
      return this.accessToken;
    }

    logger.info('Fetching new Port API access token...');
    
    try {
      const response = await axios.post(`${this.portApiUrl}/auth/access_token`, {
        clientId: this.config.clientId,
        clientSecret: this.config.clientSecret,
      });

      this.accessToken = response.data.accessToken;
      // Token typically expires in 1 hour, refresh 5 minutes before
      this.tokenExpiry = Date.now() + (55 * 60 * 1000);
      
      logger.info('Access token obtained');
      return this.accessToken;
    } catch (error) {
      logger.error('Failed to get access token:', error.response?.data || error.message);
      throw error;
    }
  }

  /**
   * Update action run status in Port
   */
  async updateActionRun(runId, updates) {
    const token = await this.getAccessToken();
    
    try {
      const response = await axios.patch(
        `${this.portApiUrl}/actions/runs/${runId}`,
        updates,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );

      logger.debug(`Updated action run ${runId}`);
      return response.data;
    } catch (error) {
      if (this._isSynchronizedActionError(error)) {
        logger.debug(`Cannot update action run ${runId} (action is synchronized): ${error.response?.data?.message || error.message}`);
      } else {
        logger.error(`Failed to update action run ${runId}:`, error.response?.data || error.message);
      }
      throw error;
    }
  }

  /**
   * Add log entry to action run
   */
  async addActionRunLog(runId, message, terminationStatus = null, statusLabel = null) {
    const token = await this.getAccessToken();
    
    const body = { message };
    if (terminationStatus) body.terminationStatus = terminationStatus;
    if (statusLabel) body.statusLabel = statusLabel;

    try {
      const response = await axios.post(
        `${this.portApiUrl}/actions/runs/${runId}/logs`,
        body,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        }
      );

      logger.debug(`Added log to action run ${runId}`);
      return response.data;
    } catch (error) {
      if (this._isSynchronizedActionError(error)) {
        logger.debug(`Cannot add log to action run ${runId} (action is synchronized): ${error.response?.data?.message || error.message}`);
      } else {
        logger.error(`Failed to add log to action run ${runId}:`, error.response?.data || error.message);
      }
      throw error;
    }
  }

  /**
   * Create or update entity in Port
   */
  async upsertEntity(blueprintId, entityData, runId = null) {
    const token = await this.getAccessToken();
    
    const params = runId ? { run_id: runId } : {};

    try {
      const response = await axios.post(
        `${this.portApiUrl}/blueprints/${blueprintId}/entities`,
        entityData,
        {
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
          params,
        }
      );

      logger.info(`Created/Updated entity: ${entityData.identifier} in blueprint: ${blueprintId}`);
      return response.data;
    } catch (error) {
      logger.error(`Failed to upsert entity:`, error.response?.data || error.message);
      throw error;
    }
  }
}

module.exports = PortClient;

