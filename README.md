# AWS Secrets Manager Self-Service Action (Webhook-based)

A standalone Port self-service action that creates and updates AWS Secrets Manager secrets via webhooks.

## Why Webhooks?

**No persistent connections** - Event-driven, only active when needed  
**Simpler deployment** - Just an HTTP server  
**Serverless-friendly** - Can be deployed as a Lambda function  
**Lower resource usage** - No Kafka consumer overhead  
**Easier to scale** - Each request is independent  

## Features

- Create AWS secrets
- Update existing AWS secrets
- Upsert (create or update) secrets
- Real-time progress reporting to Port
- Optional entity creation in Port (disabled by default, configurable via env var)
- Support for JSON and string secrets
- AWS IAM role or credential-based authentication
- Support for temporary credentials (with session tokens)
- Flexible property naming (secretName/secret_name/secret_key)
- Comprehensive error handling with helpful messages
- Startup validation for configuration

## Setup

### 1. Install Dependencies

```bash
yarn install
```

### 2. Configure Environment

Copy `.env.example` to `.env` and fill in your credentials:

```bash
cp .env.example .env
```

Edit `.env` with your Port and AWS credentials:

```bash
# Port Configuration
PORT_CLIENT_ID=your-port-client-id
PORT_CLIENT_SECRET=your-port-client-secret

# AWS Configuration
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your-aws-access-key-id
AWS_SECRET_ACCESS_KEY=your-aws-secret-access-key
# Optional: Required only for temporary credentials (ASIA prefix)
AWS_SESSION_TOKEN=your-aws-session-token

# Webhook Server
WEBHOOK_PORT=3000
WEBHOOK_PATH=/webhook

# Port Entity Creation (Optional)
PORT_CREATE_ENTITY=false  # Set to 'true' to automatically create/update entities in Port blueprints
PORT_BLUEPRINT_ID=secret  # Default blueprint ID for entity creation
```

**Note on AWS Credentials:**
- For **permanent IAM user credentials**: Only `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are required
- For **temporary credentials** (from AWS STS, SSO, or IAM roles): You also need `AWS_SESSION_TOKEN`
- If no credentials are provided, the service will attempt to use the default AWS credential chain (IAM roles, `~/.aws/credentials`, etc.)

### 3. Run the Server

```bash
yarn start
```

The server will start on port 3000 (or `WEBHOOK_PORT` from `.env`).

### 3.5. Expose with ngrok (for local development)

To expose your local server to the internet for testing:

1. Install ngrok: https://ngrok.com/download
2. Start your server: `yarn start`
3. In another terminal, run: `ngrok http 3000`
4. Copy the HTTPS URL (e.g., `https://c9ca081ce7d3.ngrok-free.app`)
5. Your webhook URL will be: `https://c9ca081ce7d3.ngrok-free.app/webhook`

**Note**: Free ngrok URLs change each time you restart ngrok. For production, use a static domain or deploy to a server.

### 4. Configure Port Action

In Port, create a self-service action with:

- **Identifier**: `manage_aws_secret`
- **Invocation Type**: Webhook
- **Webhook URL**: `https://your-server.com/webhook` (or your ngrok URL for testing)
- **Synchronized**: `true` (recommended - ensures proper success/failure reporting)
- **User Inputs**: See [Action Configuration](#action-configuration) below

**Important**: The server supports both synchronized and non-synchronized actions. For synchronized actions, the webhook processes the request synchronously and returns the result in the response, ensuring accurate status reporting in Port.

## Action Configuration

### Port Action JSON Schema

```json
{
  "properties": {
    "secretName": {
      "type": "string",
      "title": "Secret Name",
      "description": "Name of the AWS secret (e.g., myapp/database/password). Also accepts 'secret_name' or 'secret_key' as property names."
    },
    "secretValue": {
      "type": "string",
      "title": "Secret Value",
      "description": "Secret value (can be JSON string for complex secrets). Also accepts 'secret_value' as property name."
    },
    "operation": {
      "type": "string",
      "title": "Operation",
      "enum": ["create", "update", "upsert"],
      "default": "upsert",
      "description": "create: only create new secret, update: only update existing, upsert: create or update"
    },
    "description": {
      "type": "string",
      "title": "Description",
      "description": "Optional description for the secret"
    },
    "region": {
      "type": "string",
      "title": "AWS Region",
      "default": "us-east-1",
      "description": "AWS region where the secret will be stored"
    },
    "blueprintId": {
      "type": "string",
      "title": "Blueprint ID",
      "description": "Port blueprint ID to create/update entity. Defaults to 'secret' or PORT_BLUEPRINT_ID env var"
    },
    "createEntity": {
      "type": "boolean",
      "title": "Create Entity in Port",
      "default": false,
      "description": "Whether to create/update an entity in Port. Can also be controlled via PORT_CREATE_ENTITY environment variable (default: false)"
    }
  },
  "required": ["secretName", "secretValue"]
}
```

## Usage Examples

### Simple String Secret

```json
{
  "secretName": "myapp/database/password",
  "secretValue": "my-secret-password-123",
  "operation": "upsert"
}
```

### JSON Secret

```json
{
  "secretName": "myapp/config",
  "secretValue": "{\"database\": {\"host\": \"db.example.com\", \"port\": 5432}}",
  "operation": "upsert"
}
```

## Deployment Options

### Option 1: Traditional Server

Run as a Node.js service:

```bash
yarn start
```

### Option 2: Docker

```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json yarn.lock ./
RUN yarn install --production
COPY . .
EXPOSE 3000
CMD ["yarn", "start"]
```

### Option 3: Serverless (AWS Lambda)

The webhook server can be easily adapted for Lambda. The webhook endpoint can be wrapped in a Lambda handler.

## Port Entity Creation

By default, the service does **not** create or update entities in Port blueprints. You can enable this feature in two ways:

### Option 1: Environment Variable (Global Setting)

Set `PORT_CREATE_ENTITY=true` in your `.env` file to enable entity creation for all actions:

```bash
PORT_CREATE_ENTITY=true
PORT_BLUEPRINT_ID=secret  # Optional: default blueprint ID
```

### Option 2: Action Property (Per-Action)

Set `createEntity: true` in the action properties to enable it for specific actions:

```json
{
  "properties": {
    "secretName": "myapp/database/password",
    "secretValue": "my-secret-password",
    "createEntity": true,
    "blueprintId": "secret"
  }
}
```

**Priority**: Action properties override environment variables. If `createEntity` is explicitly set in properties, that value takes precedence.

**Entity Properties Created**:
- `secret_name`: The name of the AWS secret
- `secret_arn`: The ARN of the secret
- `secret_version`: The version ID of the secret
- `region`: The AWS region
- `operation`: The operation performed (create/update/upsert)
- `last_updated`: ISO timestamp of when it was last updated

## AWS Configuration

### Credentials

The service supports multiple ways to provide AWS credentials:

1. **Environment Variables** (recommended for local development):
   ```bash
   AWS_REGION=us-east-1
   AWS_ACCESS_KEY_ID=your-access-key
   AWS_SECRET_ACCESS_KEY=your-secret-key
   AWS_SESSION_TOKEN=your-session-token  # Only for temporary credentials
   ```

2. **Action Properties**: Credentials can be passed per-action via properties:
   - `awsAccessKeyId`
   - `awsSecretAccessKey`
   - `awsSessionToken` (for temporary credentials)
   - `region`

3. **Default Credential Chain**: If no explicit credentials are provided, the service will use:
   - IAM roles (when running on EC2, ECS, Lambda)
   - `~/.aws/credentials` file
   - Environment variables from AWS CLI

### IAM Permissions

The service requires the following AWS IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:UpdateSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "*"
    }
  ]
}
```

### Temporary Credentials

If you're using temporary credentials (e.g., from AWS SSO, STS, or IAM roles), you must also provide `AWS_SESSION_TOKEN`. Temporary credentials are identified by an access key starting with `ASIA`.

**Getting temporary credentials:**
```bash
# From AWS CLI
aws configure export-credentials --format env

# From AWS SSO
aws sso login
aws configure export-credentials --format env
```

## Testing

### Health Check

```bash
curl http://localhost:3000/health
```

### Status

```bash
curl http://localhost:3000/status
```

### Test Webhook (Manual)

```bash
curl -X POST http://localhost:3000/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "context": {
      "runId": "test-run-123",
      "by": {
        "email": "test@example.com"
      }
    },
    "action": {
      "identifier": "manage_aws_secret"
    },
    "properties": {
      "secretName": "test/secret",
      "secretValue": "test-value",
      "operation": "upsert"
    }
  }'
```

## Logging

Logs are written to:
- Console (colorized)
- `logs/combined.log` (all logs, JSON format)
- `logs/error.log` (errors only, JSON format)

Set log level via `LOG_LEVEL` environment variable (error, warn, info, http, debug).

## Error Handling

The service provides comprehensive error handling:

- **Configuration Validation**: On startup, the server validates required environment variables and provides helpful warnings/errors
- **AWS Credential Errors**: Clear error messages when credentials are invalid, expired, or missing
- **Synchronized Actions**: Errors are properly reported to Port for synchronized actions
- **Helpful Messages**: Error messages include suggestions for fixing common issues (e.g., missing session tokens for temporary credentials)

## Troubleshooting

### "AWS credentials are invalid or expired"
- Verify your `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are correct
- If using temporary credentials (ASIA prefix), ensure `AWS_SESSION_TOKEN` is set
- Check if credentials have expired (temporary credentials typically expire after 1 hour)
- Verify the credentials have the required Secrets Manager permissions

### "Action shows as successful but secret wasn't created"
- Ensure your action is configured as `synchronized: true` in Port
- Check server logs for actual error messages
- Verify AWS credentials are valid and have proper permissions

### "Cannot update action run" or "Action run already finished"
- These are expected messages for synchronized actions (logged at debug level)
- The action will still complete successfully - these are just informational

## License

ISC

