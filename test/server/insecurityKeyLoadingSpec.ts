/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import chai from 'chai'
import crypto from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'
import jwt from 'jsonwebtoken'

const expect = chai.expect
const jwtKeyFile = path.resolve('encryptionkeys', 'jwt.key')
const insecurityModulePath = '../../lib/insecurity'

type SecurityModule = typeof import('../../lib/insecurity')

const derivePublicKey = (privateKey: string) =>
  crypto.createPublicKey(privateKey).export({ type: 'pkcs1', format: 'pem' }).toString()

const generatePrivateKey = () =>
  crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'pkcs1', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs1', format: 'pem' }
  }).privateKey

const loadSecurity = (): SecurityModule => {
  const resolvedModulePath = require.resolve(insecurityModulePath)
  delete require.cache[resolvedModulePath]
  return require(insecurityModulePath) as SecurityModule
}

describe('insecurity JWT key loading', () => {
  const originalJwtPrivateKey = process.env.JWT_PRIVATE_KEY
  const originalJwtPublicKey = process.env.JWT_PUBLIC_KEY
  const originalKey = fs.existsSync(jwtKeyFile) ? fs.readFileSync(jwtKeyFile, 'utf8') : undefined

  beforeEach(() => {
    delete process.env.JWT_PRIVATE_KEY
    delete process.env.JWT_PUBLIC_KEY
    if (fs.existsSync(jwtKeyFile)) fs.unlinkSync(jwtKeyFile)
    delete require.cache[require.resolve(insecurityModulePath)]
  })

  afterEach(() => {
    delete require.cache[require.resolve(insecurityModulePath)]
  })

  after(() => {
    if (originalJwtPrivateKey === undefined) delete process.env.JWT_PRIVATE_KEY
    else process.env.JWT_PRIVATE_KEY = originalJwtPrivateKey
    if (originalJwtPublicKey === undefined) delete process.env.JWT_PUBLIC_KEY
    else process.env.JWT_PUBLIC_KEY = originalJwtPublicKey
    if (originalKey === undefined) {
      if (fs.existsSync(jwtKeyFile)) fs.unlinkSync(jwtKeyFile)
    } else {
      fs.writeFileSync(jwtKeyFile, originalKey, { encoding: 'utf8', mode: 0o600 })
    }
  })

  it('uses JWT_PRIVATE_KEY when it is set', () => {
    const envPrivateKey = generatePrivateKey()
    const filePrivateKey = generatePrivateKey()
    process.env.JWT_PRIVATE_KEY = envPrivateKey
    fs.writeFileSync(jwtKeyFile, filePrivateKey, { encoding: 'utf8', mode: 0o600 })

    const security = loadSecurity()

    expect(security.publicKey).to.equal(derivePublicKey(envPrivateKey))
  })

  it('falls back to encryptionkeys/jwt.key when JWT_PRIVATE_KEY is not set', () => {
    const filePrivateKey = generatePrivateKey()
    fs.writeFileSync(jwtKeyFile, filePrivateKey, { encoding: 'utf8', mode: 0o600 })

    const security = loadSecurity()

    expect(security.publicKey).to.equal(derivePublicKey(filePrivateKey))
  })

  it('rejects a mismatched JWT_PUBLIC_KEY', () => {
    process.env.JWT_PRIVATE_KEY = generatePrivateKey()
    process.env.JWT_PUBLIC_KEY = derivePublicKey(generatePrivateKey())

    expect(() => loadSecurity()).to.throw('JWT_PUBLIC_KEY does not match JWT_PRIVATE_KEY')
  })

  it('signs and verifies JWTs with the externalized key', () => {
    const filePrivateKey = generatePrivateKey()
    fs.writeFileSync(jwtKeyFile, filePrivateKey, { encoding: 'utf8', mode: 0o600 })
    const security = loadSecurity()
    const token = security.authorize({ data: { email: 'test@juice-sh.op' } })
    const decoded = jwt.verify(token, security.publicKey) as { data: { email: string } }

    expect(decoded.data.email).to.equal('test@juice-sh.op')
    expect(security.verify(token)).to.equal(true)
  })

  it('loads the key during startup and persists a generated fallback key', () => {
    const security = loadSecurity()
    const persistedPrivateKey = fs.readFileSync(jwtKeyFile, 'utf8')

    expect(fs.existsSync(jwtKeyFile)).to.equal(true)
    expect(persistedPrivateKey).to.not.equal('')
    expect(fs.statSync(jwtKeyFile).mode & 0o777).to.equal(0o600)
    expect(security.publicKey).to.equal(derivePublicKey(persistedPrivateKey))
  })

  it('rejects a fallback key with unsafe permissions', () => {
    fs.writeFileSync(jwtKeyFile, generatePrivateKey(), { encoding: 'utf8', mode: 0o644 })

    expect(() => loadSecurity()).to.throw()
  })

  it('does not follow a symlink when loading the fallback key', function () {
    if (process.platform === 'win32') this.skip()
    const target = path.resolve('encryptionkeys', 'jwt.key.target')
    fs.writeFileSync(target, generatePrivateKey(), { encoding: 'utf8', mode: 0o600 })
    fs.symlinkSync(target, jwtKeyFile)

    expect(() => loadSecurity()).to.throw()
    fs.unlinkSync(jwtKeyFile)
    fs.unlinkSync(target)
  })
})
