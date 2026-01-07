# AWS Secrets Manager Self-Service Action (Webhook-based)

A standalone Port self-service action that creates and updates AWS Secrets Manager secrets via webhooks.

## Why Webhooks?

**No persistent connections** - Event-driven, only active when needed  
**Simpler deployment** - Just an HTTP server  
**Serverless-friendly** - Can be deployed as a Lambda function  
**Lower resource usage** - No Kafka consumer overhead  
**Easier to scale** - Each request is independent  

## Quickstart

1. **Install dependencies**

   ```bash
   yarn install
   ```

2. **Configure environment**

   ```bash
   cp .env.example .env
   # then edit .env with your Port and AWS credentials
   ```

3. **Run the server**

   ```bash
   yarn start
   ```

   The server listens on `WEBHOOK_PORT` (default `3000`) and exposes:

   - `POST /webhook` – Port action webhook endpoint
   - `GET /health` – liveness probe
   - `GET /status` – basic service info

4. **Configure a Port self-service action**

   - Invocation type: **Webhook**  
   - Webhook URL: `https://your-server.com/webhook` (or your ngrok URL in development)  
   - Synchronized: `true` (recommended)  
   - Inputs: at least `secretName`, `secretValue`, and optionally `operation` (`create`/`update`/`upsert`)

## Features

### Core Functionality
- Create AWS secrets
- Update existing AWS secrets
- Upsert (create or update) secrets
- Real-time progress reporting to Port
- Optional entity creation in Port (disabled by default, configurable via env var)
- Support for JSON and string secrets
- Flexible property naming (secretName/secret_name/secret_key)

### Security
- **HMAC-SHA256 signature verification** for webhook authenticity
- **IP address allowlisting** to restrict access
- **Timestamp verification** to prevent replay attacks
- **Rate limiting** per IP address
- **Automatic decryption** of Port encrypted inputs (AES-256-GCM)
- Secret values never logged

### AWS Integration
- AWS IAM role or credential-based authentication
- Support for temporary credentials (with session tokens)
- Default AWS credential chain support
- Comprehensive error handling with helpful messages

### Operations
- Synchronized and non-synchronized action support
- Startup validation for configuration
- Health check and status endpoints
- Structured logging (console + file)

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

# Webhook Security (Recommended for Production)
WEBHOOK_SECRET=your-port-client-secret  # IMPORTANT: Use your PORT_CLIENT_SECRET for signature verification
ALLOWED_IPS=52.1.2.3,52.4.5.6           # Optional: Comma-separated list of allowed IP addresses
MAX_REQUEST_AGE=300                      # Maximum age of requests in seconds (default: 300)
ENABLE_RATE_LIMIT=true                   # Enable rate limiting (default: true)
MAX_REQUESTS_PER_MINUTE=100              # Maximum requests per IP per minute (default: 100)

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
      "description": "Secret value (can be JSON string for complex secrets). Also accepts 'secret_value' as property name. If encrypted with 'aes256-gcm' in Port, it will be automatically decrypted before storing in AWS."
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

#### Using Docker Compose (Recommended)

1. Create a `.env` file with your credentials (see [Configure Environment](#2-configure-environment))
2. Run the service:

```bash
docker-compose up -d
```

The service will be available on port 3000 (or whatever `WEBHOOK_PORT` is set to).

#### Using Docker directly

```bash
# Build the image
docker build -t aws-secrets-ssa .

# Run the container
docker run -d \
  --name aws-secrets-ssa \
  -p 3000:3000 \
  --env-file .env \
  aws-secrets-ssa
```

**Note**: Make sure your `.env` file contains all required environment variables (see [Configure Environment](#2-configure-environment)).

### Option 3: Serverless (AWS Lambda)

The webhook server can be easily adapted for Lambda. The webhook endpoint can be wrapped in a Lambda handler.

### Option 4: Docker (Production)

For production deployments, you can use Docker with the provided `Dockerfile` and `docker-compose.yml`.

**Features:**
- Non-root user for security
- Health checks included
- Log volume mounting
- Automatic restart on failure
- Environment variable management

**Build and deploy:**
```bash
# Build the image
docker build -t aws-secrets-ssa .

# Or use docker-compose
docker-compose up -d --build
```

**View logs:**
```bash
docker-compose logs -f
# or
docker logs -f aws-secrets-ssa
```

**Stop the service:**
```bash
docker-compose down
# or
docker stop aws-secrets-ssa
```

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

These endpoints are suitable for Docker / Kubernetes liveness and readiness probes.

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

## Security

### Transport Security
- **HTTPS Required**: Run this service behind HTTPS (load balancer, API gateway, or ingress). Do not expose it over plain HTTP on the public internet.
- Port webhooks should only be accessible over secure connections.

### Webhook Security

The service implements multiple layers of security to protect the webhook endpoint:

#### 1. Signature Verification (HMAC-SHA256)
Port signs all webhook requests using HMAC-SHA256. The service verifies these signatures to ensure requests are authentic.

**Configuration:**
```bash
WEBHOOK_SECRET=your-port-client-secret  # Must match your PORT_CLIENT_SECRET
```

**How it works:**
- Port sends a signature in the `x-port-signature` header (format: `v1,<base64_signature>`)
- Port sends a timestamp in the `x-port-timestamp` header
- The service verifies the signature matches the expected HMAC-SHA256 hash
- Uses constant-time comparison to prevent timing attacks

**Important:** If `WEBHOOK_SECRET` is not configured, signature verification is disabled (not recommended for production).

#### 2. IP Address Allowlisting
Restrict webhook access to specific IP addresses (e.g., Port's webhook IPs).

**Configuration:**
```bash
ALLOWED_IPS=52.1.2.3,52.4.5.6,10.0.0.0/24  # Comma-separated list, supports CIDR notation
```

**How it works:**
- Checks the client IP against the allowlist
- Supports `x-forwarded-for` and `x-real-ip` headers for proxy scenarios
- If not configured, IP verification is skipped

#### 3. Timestamp Verification (Replay Attack Prevention)
Prevents replay attacks by rejecting old requests.

**Configuration:**
```bash
MAX_REQUEST_AGE=300  # Maximum age in seconds (default: 5 minutes)
```

**How it works:**
- Verifies the `x-port-timestamp` header is within the allowed age
- Rejects requests older than `MAX_REQUEST_AGE` seconds
- Also rejects requests with timestamps in the future (clock skew tolerance: 60 seconds)

#### 4. Rate Limiting
Protects against abuse by limiting requests per IP address.

**Configuration:**
```bash
ENABLE_RATE_LIMIT=true           # Enable/disable rate limiting
MAX_REQUESTS_PER_MINUTE=100      # Maximum requests per IP per minute
```

**How it works:**
- Tracks requests per IP address in a sliding window
- Returns HTTP 429 (Too Many Requests) when limit is exceeded
- Automatically cleans up old entries every 5 minutes

### Secret Handling
- Secret values are **never logged** by this service.
- When `secretValue` is configured with `"encryption": "aes256-gcm"` in Port, the value is transparently decrypted using `PORT_CLIENT_SECRET` and only the decrypted value is sent to AWS Secrets Manager.
- Plaintext `secretValue` is accepted but still not logged.

### AWS Credentials
- Prefer **IAM roles** (EC2/ECS/Lambda/IRSA) over long-lived access keys.
- If you do use access keys, store them in environment variables or a secret manager, not in source control.
- Use least-privilege IAM policies: restrict Secrets Manager permissions to only the secrets or paths you actually manage.

### Security Best Practices

**For Production Deployments:**
1. ✅ Enable signature verification (`WEBHOOK_SECRET`)
2. ✅ Configure IP allowlisting (`ALLOWED_IPS`) with Port's webhook IPs
3. ✅ Enable rate limiting (`ENABLE_RATE_LIMIT=true`)
4. ✅ Use HTTPS with valid TLS certificates
5. ✅ Set appropriate `MAX_REQUEST_AGE` (default 300s is recommended)
6. ✅ Use IAM roles instead of access keys when possible
7. ✅ Monitor logs for unauthorized access attempts

**For Development/Testing:**
- Signature verification can be disabled by not setting `WEBHOOK_SECRET` (not recommended)
- IP allowlisting can be skipped by not setting `ALLOWED_IPS`
- Use ngrok or similar tools for local testing with HTTPS

### Security Headers Reference

Port sends the following headers with webhook requests:

| Header | Description | Example |
|--------|-------------|---------|
| `x-port-signature` | HMAC-SHA256 signature of the request | `v1,abc123...` |
| `x-port-timestamp` | Unix timestamp in milliseconds | `1704628800000` |
| `x-forwarded-for` | Client IP (if behind proxy) | `52.1.2.3` |
| `content-type` | Request content type | `application/json` |

The service uses these headers to verify request authenticity and prevent attacks.

## Encrypted Inputs

The service automatically handles encrypted inputs from Port. When you configure a property with `"encryption": "aes256-gcm"` in your Port action, Port will encrypt the value before sending it to the webhook.

**Automatic Decryption:**
- The service detects encrypted values (base64-encoded AES-256-GCM)
- Uses `PORT_CLIENT_SECRET` to decrypt the value
- Stores the **decrypted** value in AWS Secrets Manager (not the encrypted one)

**Requirements:**
- `PORT_CLIENT_SECRET` must be set in your environment
- The client secret must be at least 32 characters (uses first 32 bytes as decryption key)

**Note:** If decryption fails, the action will fail with a clear error message. This ensures encrypted values are never stored in AWS without being decrypted first.

## Error Handling

The service provides comprehensive error handling:

- **Configuration Validation**: On startup, the server validates required environment variables and provides helpful warnings/errors
- **AWS Credential Errors**: Clear error messages when credentials are invalid, expired, or missing
- **Encryption/Decryption Errors**: Clear errors if encrypted values cannot be decrypted
- **Synchronized Actions**: Errors are properly reported to Port for synchronized actions
- **Helpful Messages**: Error messages include suggestions for fixing common issues (e.g., missing session tokens for temporary credentials)

## Troubleshooting

### AWS Credentials Issues

**"AWS credentials are invalid or expired"**
- Verify your `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` are correct
- If using temporary credentials (ASIA prefix), ensure `AWS_SESSION_TOKEN` is set
- Check if credentials have expired (temporary credentials typically expire after 1 hour)
- Verify the credentials have the required Secrets Manager permissions

**"Action shows as successful but secret wasn't created"**
- Ensure your action is configured as `synchronized: true` in Port
- Check server logs for actual error messages
- Verify AWS credentials are valid and have proper permissions

### Webhook Security Issues

**"Invalid webhook signature" (HTTP 401)**
- Ensure `WEBHOOK_SECRET` matches your `PORT_CLIENT_SECRET` exactly
- Verify Port is sending the `x-port-signature` and `x-port-timestamp` headers
- Check server logs (set `LOG_LEVEL=debug`) to see signature comparison details
- Ensure the webhook endpoint is receiving the raw request body (required for signature verification)

**"Request from unauthorized IP address" (HTTP 403)**
- Verify the client IP is in your `ALLOWED_IPS` list
- Check if you're behind a proxy/load balancer - the service looks for `x-forwarded-for` header
- Temporarily disable IP filtering to test (remove `ALLOWED_IPS` from env)
- Check server logs to see which IP address is being detected

**"Request timestamp invalid or too old" (HTTP 401)**
- Check if your server's clock is synchronized (use NTP)
- Verify `MAX_REQUEST_AGE` is set appropriately (default: 300 seconds)
- Ensure Port's webhook is reaching your server quickly (network latency issues)
- Check for clock skew between your server and Port's servers

**"Rate limit exceeded" (HTTP 429)**
- Increase `MAX_REQUESTS_PER_MINUTE` if you have legitimate high traffic
- Check if you're being targeted by automated requests
- Verify the IP address triggering the limit in server logs
- Consider implementing additional authentication if needed

### Action Execution Issues

**"Cannot update action run" or "Action run already finished"**
- These are expected messages for synchronized actions (logged at debug level)
- The action will still complete successfully - these are just informational
- For synchronized actions, Port determines success/failure from the HTTP response, not API calls

**"Failed to decrypt Port encrypted secret"**
- Ensure `PORT_CLIENT_SECRET` is set and matches the secret used in Port
- Verify the client secret is at least 32 characters long
- Check that the property is configured with `"encryption": "aes256-gcm"` in Port
- Review server logs for specific decryption error details

### General Debugging

**Enable debug logging:**
```bash
LOG_LEVEL=debug yarn start
```

This will show:
- Detailed signature verification steps
- IP address detection
- Timestamp validation
- Request/response details (secrets are still never logged)

## License

ISC

