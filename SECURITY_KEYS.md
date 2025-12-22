# Security Keys Configuration

## Overview

This document describes how to configure JWT private keys and HMAC keys securely for production deployments of Juice Shop.

## Background

Previously, RSA private keys and HMAC keys were hard-coded in the source code (`lib/insecurity.ts`), which posed a significant security risk:
- Keys could be extracted from source code or compiled artifacts
- The same keys would be used across all deployments
- Key rotation required code changes and redeployment
- Leaked keys could not be quickly rotated

## Current Implementation

The application now supports loading keys from environment variables, with file-based and hard-coded fallbacks for development/testing purposes.

### JWT Private Key

The JWT signing key can be configured in the following priority order:

1. **Environment Variable** (Recommended for Production): `JWT_PRIVATE_KEY`
   - Set this to your RSA private key in PEM format
   - Example: `JWT_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"`

2. **File-based** (Suitable for Development): `encryptionkeys/jwt.key`
   - If no environment variable is set, the application will read from this file
   - A warning will be logged if used in production

3. **Fallback** (Not Recommended): Placeholder key
   - If neither environment variable nor file exists, a placeholder is used
   - An error will be logged

### HMAC Key

The HMAC key for various hashing operations can be configured as:

1. **Environment Variable** (Recommended for Production): `HMAC_KEY`
   - Set this to a strong random string
   - Generate using: `openssl rand -base64 32`
   - Example: `HMAC_KEY="your_secure_random_key_here"`

2. **Fallback** (Development Only): Hard-coded default value
   - A warning will be logged if used in production

## Production Deployment

For production deployments, you **MUST**:

1. Generate new RSA key pair:
   ```bash
   # Generate private key
   openssl genrsa -out jwt.key 2048
   
   # Generate public key
   openssl rsa -in jwt.key -pubout -outform PEM -out jwt.pub
   ```

2. Generate a strong HMAC key:
   ```bash
   openssl rand -base64 32
   ```

3. Set environment variables:
   ```bash
   export JWT_PRIVATE_KEY="$(cat jwt.key)"
   export HMAC_KEY="your_generated_hmac_key"
   ```

4. Store keys securely:
   - Use environment-specific secret management (AWS Secrets Manager, Azure Key Vault, etc.)
   - Never commit production keys to version control
   - Implement key rotation policies

## Development/Testing

For development and testing purposes, the application includes default keys:
- `encryptionkeys/jwt.key` - RSA private key
- `encryptionkeys/jwt.pub` - RSA public key

These keys are suitable for local development but **must not** be used in production.

## Warnings

The application will log warnings when:
- Default keys are used in production environment (`NODE_ENV=production`)
- No JWT private key is found (critical error)

## Migration from Previous Versions

If you were using the previous hard-coded keys in production:

1. **Immediate Action Required**: The hard-coded keys were publicly exposed in source code
2. Generate new keys immediately (see Production Deployment section)
3. Update all deployments with new keys
4. Invalidate all existing JWT tokens by restarting services with new keys
5. Monitor for unauthorized access attempts

## Security Best Practices

1. **Never commit secrets**: Ensure `.env` files and production keys are in `.gitignore`
2. **Key rotation**: Implement regular key rotation (recommended: every 90 days)
3. **Access control**: Limit access to production keys to essential personnel only
4. **Monitoring**: Monitor for unusual authentication patterns
5. **Backup keys**: Securely backup keys in encrypted storage

## Support

For issues related to key configuration, please refer to the main documentation or open an issue on the project repository.
