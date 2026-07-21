# Security Policy

## Supported Versions

| Version | Supported |
|---------|----------|
| 1.x     | ✅ Active |

## Reporting a Vulnerability

**Do not open a public GitHub issue.** Instead, email: security@deepvault.dev

Expect an acknowledgment within 48 hours and a fix timeline within 7 days.

## Responsible Disclosure

We practice coordinated disclosure. Please give us reasonable time to patch
before publishing details.

## OpSec Notes

- Never commit real API keys — use `.env` only
- The `.env` file is in `.gitignore` — verify before committing
- All investigation data is stored in Docker volumes — encrypt at rest
- Review all outgoing API calls — some services log query metadata
