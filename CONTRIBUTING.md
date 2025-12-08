# Contributing

Thank you for your interest in contributing to this project! Contributions are welcome in the form of bug reports, feature requests, documentation improvements, and pull requests.

## Ways to Contribute

- **Bug reports**: Report issues you encounter when using the service.
- **Feature requests**: Suggest improvements to usability, security, or functionality.
- **Documentation**: Improve or clarify the README, examples, or comments.
- **Code contributions**: Fix bugs, add tests, or implement new features.

## Development Setup

1. **Clone the repository**

   ```bash
   git clone <repo-url>
   cd aws-secrets-ssa
   ```

2. **Install dependencies**

   ```bash
   yarn install
   ```

3. **Configure environment**

   Copy the example environment file and adjust values as needed:

   ```bash
   cp .env.example .env
   ```

   At minimum, you will usually want to set:

   - `PORT_CLIENT_ID`
   - `PORT_CLIENT_SECRET`
   - `AWS_REGION`
   - AWS credentials (either via environment variables or your local AWS configuration)

4. **Run the server**

   ```bash
   yarn start
   ```

   The server will listen on `WEBHOOK_PORT` (default `3000`).

5. **Exercise the webhook manually**

   You can send a test request using the example in `README.md` under **Testing**.

## Code Style and Practices

- Use modern JavaScript syntax supported by the current Node.js LTS.
- Keep logging consistent with the existing `logger` usage (no `console.log` in production code).
- Be especially careful not to log secret values or AWS credentials.

## Tests

Basic automated tests are encouraged for new functionality, especially where behavior is security- or error-handling related.

If you add or modify logic in modules like `aws-secrets-service` or the webhook handling in `server.js`, consider adding corresponding tests. A typical pattern would be:

- Unit tests for AWS-related logic using mocked AWS SDK clients.
- Unit tests for request handling using an HTTP testing library (e.g., supertest) if you introduce or modify routes.

If a test suite is added in this repository, document how to run it here (for example, `yarn test`).

## Pull Request Guidelines

- **Small, focused changes** are easier to review and merge.
- Include a brief description of what the change does and why it is needed.
- If applicable, describe how you tested the change (manual steps or automated tests).
- Avoid unrelated formatting or refactoring changes in the same PR.

## Reporting Security Issues

For potential security vulnerabilities, please **do not** open a public issue. Instead, follow the process described in `SECURITY.md` so the issue can be assessed and addressed responsibly.
