# Security Policy

## Supported Versions

This project is maintained on a best-effort basis. In general, the latest main branch and the most recent tagged release are considered supported.

If you are running an older version and encounter a security issue, please try to reproduce it on the latest version before reporting.

## Reporting a Vulnerability

If you believe you have found a security vulnerability in this project:

1. **Do not** open a public GitHub issue describing the vulnerability in detail.
2. Instead, contact the maintainers privately (for example via the contact information in the repository or organization profile) and include:
   - A clear description of the issue and potential impact.
   - Steps to reproduce, including configuration details where relevant.
   - Any proof-of-concept code or requests you used.
3. Allow reasonable time for investigation and remediation before any public disclosure.

We take security issues seriously and will:

- Confirm receipt of your report.
- Investigate the issue.
- Provide an estimated timeline for a fix where possible.
- Credit you in the release notes if you would like.

## Security Expectations

This service is designed to be used as a webhook-based integration between Port and AWS Secrets Manager. Because it processes sensitive secret values and AWS credentials, you should follow these guidelines in production:

- **Transport Security**
  - Run the service only behind HTTPS (e.g., load balancer, API gateway, ingress controller).
  - Do not expose plain HTTP endpoints directly to the public internet.

- **Authentication and Access Control**
  - Restrict access to the `/webhook` endpoint so that only Port can call it (for example, via network controls, IP allow-lists, API keys, OAuth, or mTLS at the edge).
  - Avoid exposing this service on the open internet without authentication.

- **Secret Handling**
  - Secret values are never logged by this service.
  - When using Port's `"encryption": "aes256-gcm"` property option, encrypted values are decrypted in-memory using `PORT_CLIENT_SECRET` and only the decrypted value is sent to AWS Secrets Manager.
  - Plaintext secret values are supported but should still be treated as highly sensitive and protected at the network and infrastructure levels.

- **AWS Credentials**
  - Prefer short-lived, role-based credentials (IAM roles, IRSA, etc.) over long-lived access keys.
  - If you must use access keys, store them in a secure secret store or environment variables, never in source control.
  - Use least-privilege IAM policies that restrict Secrets Manager actions to only the secrets or paths that this service needs to manage.

For more operational and configuration guidance, see the **Security** section in `README.md`.
