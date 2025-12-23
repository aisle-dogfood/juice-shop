# Security Notice: Static Seed Data

## ⚠️ WARNING: Hard-coded Credentials

This directory contains static seed data files used for development and testing purposes. These files include **hard-coded credentials and sensitive information** that must NEVER be used in production environments.

## What's Included

The `users.yml` file contains:

- **Plaintext passwords** - Including weak passwords like 'admin123'
- **Admin role credentials** - Full administrative access accounts
- **TOTP secrets** - Two-factor authentication secrets in plaintext
- **Test credit card numbers** - Mock payment card data

## Security Measures

The application implements the following safeguards:

1. **Production Environment Block**: The application will refuse to load this seed data when `NODE_ENV=production`
2. **Runtime Validation**: Multiple layers check the environment before loading user data
3. **Logging Warnings**: Non-production environments log warnings when seed data is loaded

## For Production Deployments

When deploying to production:

1. **Set NODE_ENV=production** - This environment variable must be set
2. **Use Secure User Provisioning** - Implement a proper user management system
3. **Rotate All Secrets** - Never reuse any credentials from these seed files
4. **Use Strong Passwords** - Implement password complexity requirements
5. **Hash Sensitive Data** - Never store plaintext passwords or secrets

## For Development Use

This seed data is safe for:
- Local development environments
- Automated testing
- Training and demonstration purposes
- Security research and penetration testing

## Questions?

If you need to deploy this application in a production-like environment, consult the main security documentation and ensure all hard-coded credentials are replaced with secure alternatives.
