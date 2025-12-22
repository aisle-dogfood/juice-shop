/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

/* jslint node: true */
import packageJson from '../package.json'
import fs from 'node:fs'
import logger from './logger'
import config from 'config'
import jsSHA from 'jssha'
import download from 'download'
import crypto from 'node:crypto'
import clarinet from 'clarinet'
import type { Challenge } from 'data/types'
import path from 'node:path'
import { promisify } from 'node:util'
import dns from 'node:dns'

import isHeroku from './is-heroku'
import isDocker from './is-docker'
import isWindows from './is-windows'
export { default as isDocker } from './is-docker'
export { default as isWindows } from './is-windows'
// import isGitpod from 'is-gitpod') // FIXME Roll back to this when https://github.com/dword-design/is-gitpod/issues/94 is resolve
const isGitpod = () => false

const dnsLookup = promisify(dns.lookup)

const months = ['JAN', 'FEB', 'MAR', 'APR', 'MAY', 'JUN', 'JUL', 'AUG', 'SEP', 'OCT', 'NOV', 'DEC']

export const queryResultToJson = <T>(
  data: T,
  status: string = 'success'
): { data: T, status: string } => {
  return {
    status,
    data
  }
}

export const isUrl = (url: string) => {
  return startsWith(url, 'http')
}

export const startsWith = (str: string, prefix: string) => str ? str.indexOf(prefix) === 0 : false

export const endsWith = (str?: string, suffix?: string) => (str && suffix) ? str.includes(suffix, str.length - suffix.length) : false

export const contains = (str: string, element: string) => str ? str.includes(element) : false // TODO Inline all usages as this function is not adding any functionality to String.includes

export const containsEscaped = function (str: string, element: string) {
  return contains(str, element.replace(/"/g, '\\"'))
}

export const containsOrEscaped = function (str: string, element: string) {
  return contains(str, element) || containsEscaped(str, element)
}

export const unquote = function (str: string) {
  if (str && startsWith(str, '"') && endsWith(str, '"')) {
    return str.substring(1, str.length - 1)
  } else {
    return str
  }
}

export const trunc = function (str: string, length: number) {
  str = str.replace(/(\r\n|\n|\r)/gm, '')
  return (str.length > length) ? str.substr(0, length - 1) + '...' : str
}

export const version = (module?: string) => {
  if (module) {
    // @ts-expect-error FIXME Ignoring any type issue on purpose
    return packageJson.dependencies[module]
  } else {
    return packageJson.version
  }
}

let cachedCtfKey: string | undefined
const getCtfKey = () => {
  if (!cachedCtfKey) {
    if (process.env.CTF_KEY !== undefined && process.env.CTF_KEY !== '') {
      cachedCtfKey = process.env.CTF_KEY
    } else {
      const data = fs.readFileSync('ctf.key', 'utf8')
      cachedCtfKey = data
    }
  }
  return cachedCtfKey
}
export const ctfFlag = (text: string) => {
  const shaObj = new jsSHA('SHA-1', 'TEXT') // eslint-disable-line new-cap
  shaObj.setHMACKey(getCtfKey(), 'TEXT')
  shaObj.update(text)
  return shaObj.getHMAC('HEX')
}

export const toMMMYY = (date: Date) => {
  const month = date.getMonth()
  const year = date.getFullYear()
  return months[month] + year.toString().substring(2, 4)
}

export const toISO8601 = (date: Date) => {
  let day = '' + date.getDate()
  let month = '' + (date.getMonth() + 1)
  const year = date.getFullYear()

  if (month.length < 2) month = '0' + month
  if (day.length < 2) day = '0' + day

  return [year, month, day].join('-')
}

export const extractFilename = (url: string) => {
  let file = decodeURIComponent(url.substring(url.lastIndexOf('/') + 1))
  if (contains(file, '?')) {
    file = file.substring(0, file.indexOf('?'))
  }
  return file
}

/**
 * Validates if a URL is safe for server-side downloads
 * Blocks dangerous schemes, private IPs, localhost, and cloud metadata endpoints
 */
const isUrlSafeForDownload = async (urlString: string): Promise<boolean> => {
  try {
    const url = new URL(urlString)
    
    // Only allow http and https schemes
    if (!['http:', 'https:'].includes(url.protocol)) {
      logger.warn(`Blocked download attempt with invalid scheme: ${url.protocol}`)
      return false
    }

    // Block dangerous hostnames
    const hostname = url.hostname.toLowerCase()
    const blockedHostnames = [
      'localhost',
      '127.0.0.1',
      '::1',
      '0.0.0.0',
      '169.254.169.254', // AWS metadata endpoint
      'metadata.google.internal' // GCP metadata endpoint
    ]
    
    if (blockedHostnames.includes(hostname)) {
      logger.warn(`Blocked download attempt to dangerous hostname: ${hostname}`)
      return false
    }

    // Check for private IP ranges
    try {
      const { address } = await dnsLookup(hostname)
      
      // Block localhost and loopback
      if (address === '127.0.0.1' || address === '::1') {
        logger.warn(`Blocked download attempt to loopback address: ${address}`)
        return false
      }
      
      // Block private IPv4 ranges (RFC1918)
      const ipv4Parts = address.split('.')
      if (ipv4Parts.length === 4) {
        const firstOctet = parseInt(ipv4Parts[0])
        const secondOctet = parseInt(ipv4Parts[1])
        
        // 10.0.0.0/8
        if (firstOctet === 10) {
          logger.warn(`Blocked download attempt to private IP range (10.0.0.0/8): ${address}`)
          return false
        }
        
        // 172.16.0.0/12
        if (firstOctet === 172 && secondOctet >= 16 && secondOctet <= 31) {
          logger.warn(`Blocked download attempt to private IP range (172.16.0.0/12): ${address}`)
          return false
        }
        
        // 192.168.0.0/16
        if (firstOctet === 192 && secondOctet === 168) {
          logger.warn(`Blocked download attempt to private IP range (192.168.0.0/16): ${address}`)
          return false
        }
        
        // 169.254.0.0/16 (link-local)
        if (firstOctet === 169 && secondOctet === 254) {
          logger.warn(`Blocked download attempt to link-local address: ${address}`)
          return false
        }
      }
      
      // Block IPv6 link-local and unique local addresses
      if (address.includes(':')) {
        const lowerAddress = address.toLowerCase()
        // fe80::/10 (link-local)
        // fc00::/7 (unique local)
        if (lowerAddress.startsWith('fe80:') || lowerAddress.startsWith('fc') || lowerAddress.startsWith('fd')) {
          logger.warn(`Blocked download attempt to private IPv6 address: ${address}`)
          return false
        }
      }
    } catch (err) {
      logger.warn(`DNS lookup failed for ${hostname}: ${getErrorMessage(err)}`)
      return false
    }

    return true
  } catch (err) {
    logger.warn(`Invalid URL format: ${urlString}`)
    return false
  }
}

/**
 * Sanitizes a filename to prevent path traversal attacks
 */
const sanitizeFilename = (filename: string): string => {
  // Remove any path components
  const basename = path.basename(filename)
  // Remove null bytes and other dangerous characters
  return basename.replace(/[^\w\s.-]/g, '_')
}

export const downloadToFile = async (url: string, dest: string) => {
  try {
    // Validate URL is safe for download
    if (!await isUrlSafeForDownload(url)) {
      throw new Error(`URL validation failed for security reasons: ${url}`)
    }

    // Sanitize the destination path to prevent path traversal
    const destDir = path.dirname(dest)
    const destFilename = path.basename(dest)
    const sanitizedFilename = sanitizeFilename(destFilename)
    const sanitizedDest = path.join(destDir, sanitizedFilename)

    // Ensure the sanitized path is still under the intended directory
    const resolvedDest = path.resolve(sanitizedDest)
    const resolvedDestDir = path.resolve(destDir)
    if (!resolvedDest.startsWith(resolvedDestDir)) {
      throw new Error(`Path traversal attempt detected: ${dest}`)
    }

    // Download with timeout (30 seconds)
    const downloadOptions = {
      timeout: 30000, // 30 second timeout
      // Note: download package doesn't support maxRedirects directly, but has built-in redirect handling
    }
    
    const data = await download(url, undefined, downloadOptions)
    
    // Check file size limit (10MB)
    const maxSize = 10 * 1024 * 1024 // 10MB
    if (data.length > maxSize) {
      throw new Error(`Downloaded file exceeds maximum size limit (10MB): ${data.length} bytes`)
    }

    // Write to temporary file first, then rename atomically
    const tempDest = sanitizedDest + '.tmp'
    fs.writeFileSync(tempDest, data)
    fs.renameSync(tempDest, sanitizedDest)
    
    logger.info(`Successfully downloaded ${url} to ${sanitizedDest}`)
  } catch (err) {
    logger.warn('Failed to download ' + url + ' (' + getErrorMessage(err) + ')')
    throw err // Re-throw to allow caller to handle
  }
}

export const jwtFrom = ({ headers }: { headers: any }) => {
  if (headers?.authorization) {
    const parts = headers.authorization.split(' ')
    if (parts.length === 2) {
      const scheme = parts[0]
      const token = parts[1]

      if (/^Bearer$/i.test(scheme)) {
        return token
      }
    }
  }
  return undefined
}

export const randomHexString = (length: number): string => {
  return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length)
}

export interface ChallengeEnablementStatus {
  enabled: boolean
  disabledBecause: string | null
}

type SafetyModeSetting = 'enabled' | 'disabled' | 'auto'

type isEnvironmentFunction = () => boolean

export function getChallengeEnablementStatus (challenge: Challenge,
  safetyModeSetting: SafetyModeSetting = config.get<SafetyModeSetting>('challenges.safetyMode'),
  isEnvironmentFunctions: {
    isDocker: isEnvironmentFunction
    isHeroku: isEnvironmentFunction
    isWindows: isEnvironmentFunction
    isGitpod: isEnvironmentFunction
  } = { isDocker, isHeroku, isWindows, isGitpod }): ChallengeEnablementStatus {
  if (!challenge?.disabledEnv) {
    return { enabled: true, disabledBecause: null }
  }

  if (safetyModeSetting === 'disabled') {
    return { enabled: true, disabledBecause: null }
  }

  if (challenge.disabledEnv?.includes('Docker') && isEnvironmentFunctions.isDocker()) {
    return { enabled: false, disabledBecause: 'Docker' }
  }
  if (challenge.disabledEnv?.includes('Heroku') && isEnvironmentFunctions.isHeroku()) {
    return { enabled: false, disabledBecause: 'Heroku' }
  }
  if (challenge.disabledEnv?.includes('Windows') && isEnvironmentFunctions.isWindows()) {
    return { enabled: false, disabledBecause: 'Windows' }
  }
  if (challenge.disabledEnv?.includes('Gitpod') && isEnvironmentFunctions.isGitpod()) {
    return { enabled: false, disabledBecause: 'Gitpod' }
  }
  if (challenge.disabledEnv && safetyModeSetting === 'enabled') {
    return { enabled: false, disabledBecause: 'Safety Mode' }
  }

  return { enabled: true, disabledBecause: null }
}
export function isChallengeEnabled (challenge: Challenge): boolean {
  const { enabled } = getChallengeEnablementStatus(challenge)
  return enabled
}

export const parseJsonCustom = (jsonString: string) => {
  const parser = clarinet.parser()
  const result: any[] = []
  parser.onkey = parser.onopenobject = (k: any) => {
    result.push({ key: k, value: null })
  }
  parser.onvalue = (v: any) => {
    result[result.length - 1].value = v
  }
  parser.write(jsonString)
  parser.close()
  return result
}

export const toSimpleIpAddress = (ipv6: string) => {
  if (startsWith(ipv6, '::ffff:')) {
    return ipv6.substr(7)
  } else if (ipv6 === '::1') {
    return '127.0.0.1'
  } else {
    return ipv6
  }
}

export const getErrorMessage = (error: unknown) => {
  if (error instanceof Error) return error.message
  return String(error)
}

export const matchesSystemIniFile = (text: string) => {
  const match = text.match(/; for 16-bit app support/gi)
  return match !== null && match.length >= 1
}

export const matchesEtcPasswdFile = (text: string) => {
  const match = text.match(/(\w*:\w*:\d*:\d*:\w*:.*)|(Note that this file is consulted directly)/gi)
  return match !== null && match.length >= 1
}
