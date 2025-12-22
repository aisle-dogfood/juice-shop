# Hardening OWASP Juice Shop for Production Deployments

## Overview

OWASP Juice Shop is intentionally vulnerable and designed for security training and awareness. However, if you need to deploy it in a more controlled or production-like environment, you can use the following hardening configurations.

## Directory Browsing Security

### The Issue

By default, Juice Shop uses `serve-index` to enable directory browsing for various directories as part of security challenges:
- `/ftp` - File transfer directory browsing (directoryListingChallenge)
- `/.well-known` - Well-known directory browsing
- `/encryptionkeys` - Encryption keys directory browsing
- `/support/logs` - Support logs directory browsing (accessLogDisclosureChallenge)

While these are intentional vulnerabilities for CTF challenges, they can lead to information disclosure in production environments.

### The Fix

A new configuration option `server.enableDirectoryBrowsing` has been added to control directory browsing:

```yaml
server:
  enableDirectoryBrowsing: false  # Disable directory browsing for security
```

### Configuration Profiles

#### Production/Hardened Deployment

Use the `production` configuration:

```bash
NODE_ENV=production npm start
```

Or explicitly set the configuration:

```bash
NODE_CONFIG='{"server":{"enableDirectoryBrowsing":false}}' npm start
```

The `config/production.yml` file is pre-configured with:
- `server.enableDirectoryBrowsing: false` - Disables directory browsing
- `challenges.safetyMode: enabled` - Enables safety mode

#### CTF/Training Deployment

Use the `ctf` or `tutorial` configuration:

```bash
NODE_ENV=ctf npm start
# or
NODE_ENV=tutorial npm start
```

These configurations have:
- `server.enableDirectoryBrowsing: true` - Enables directory browsing for challenges

### Behavior When Disabled

When `server.enableDirectoryBrowsing` is set to `false`:
- Directory listings are not available (e.g., browsing `/ftp` will not show file listings)
- Individual files can still be accessed directly by their full path if authorization permits
- All file access controls and authorization checks remain in place
- CTF challenges requiring directory browsing will not be solvable (by design)

### Security Recommendations

For production or hardened deployments:

1. **Disable Directory Browsing**: Set `server.enableDirectoryBrowsing: false`
2. **Enable Safety Mode**: Set `challenges.safetyMode: enabled`
3. **Restrict Network Access**: Use firewall rules to limit who can access the application
4. **Use HTTPS**: Always use HTTPS in production environments
5. **Regular Updates**: Keep dependencies up to date
6. **Monitor Logs**: Regularly review access logs for suspicious activity

### Example Configuration

Create a custom configuration file `config/custom-environment-variables.yml`:

```yaml
server:
  enableDirectoryBrowsing: false
  port: 443
application:
  domain: your-domain.com
challenges:
  safetyMode: enabled
```

Then run:

```bash
NODE_ENV=custom npm start
```

## Additional Resources

- [Official Documentation](https://owasp-juice.shop)
- [Configuration Documentation](https://pwning.owasp-juice.shop/part1/running.html#configuration)
- [Security Policy](SECURITY.md)
