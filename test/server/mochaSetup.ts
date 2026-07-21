/*
 * Mocha setup: generate RSA key pair and HMAC key for tests when not provided externally
 */
import { generateKeyPairSync, randomBytes } from 'crypto'

try {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
  })

  if (!process.env.JWT_PRIVATE_KEY) process.env.JWT_PRIVATE_KEY = privateKey
  if (!process.env.JWT_PUBLIC_KEY) process.env.JWT_PUBLIC_KEY = publicKey
  if (!process.env.HMAC_KEY) process.env.HMAC_KEY = randomBytes(16).toString('hex')
  if (!process.env.DELUXE_TOKEN_KEY) process.env.DELUXE_TOKEN_KEY = randomBytes(16).toString('hex')
} catch (err) {
  // If key generation fails, leave env vars untouched; tests that require keys should provide them.
}
