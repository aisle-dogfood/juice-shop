/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import crypto from 'node:crypto'
import { type Request, type Response, type NextFunction } from 'express'

const CSRF_TOKEN_LENGTH = 32
const CSRF_COOKIE_NAME = 'XSRF-TOKEN'
const CSRF_HEADER_NAME = 'x-xsrf-token'

/**
 * Generate a random CSRF token
 */
function generateToken (): string {
  return crypto.randomBytes(CSRF_TOKEN_LENGTH).toString('hex')
}

/**
 * Middleware to generate and set CSRF token in cookie
 */
export function csrfProtection () {
  return (req: Request, res: Response, next: NextFunction) => {
    // Generate token if not present
    if (!req.cookies[CSRF_COOKIE_NAME]) {
      const token = generateToken()
      res.cookie(CSRF_COOKIE_NAME, token, {
        httpOnly: false, // Must be accessible to JavaScript for inclusion in requests
        sameSite: 'strict',
        secure: process.env.NODE_ENV === 'production'
      })
    }
    next()
  }
}

/**
 * Middleware to validate CSRF token on state-changing requests
 * @param options - Configuration options
 * @param options.excludePaths - Array of path patterns to exclude from CSRF validation
 */
export function validateCsrfToken (options: { excludePaths?: string[] } = {}) {
  const { excludePaths = [] } = options
  
  return (req: Request, res: Response, next: NextFunction) => {
    // Skip validation for safe methods
    if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
      return next()
    }

    // Skip validation for excluded paths
    const requestPath = req.path
    const isExcluded = excludePaths.some(pattern => {
      if (pattern.includes('*')) {
        const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$')
        return regex.test(requestPath)
      }
      return requestPath === pattern || requestPath.startsWith(pattern)
    })
    
    if (isExcluded) {
      return next()
    }

    // Get token from cookie and header
    const cookieToken = req.cookies[CSRF_COOKIE_NAME]
    const headerToken = req.headers[CSRF_HEADER_NAME] as string || req.body?._csrf

    // Validate token presence
    if (!cookieToken) {
      return res.status(403).json({
        error: 'CSRF token missing in cookie'
      })
    }

    if (!headerToken) {
      return res.status(403).json({
        error: 'CSRF token missing in request'
      })
    }

    // Validate token match using constant-time comparison
    if (!crypto.timingSafeEqual(Buffer.from(cookieToken), Buffer.from(headerToken))) {
      return res.status(403).json({
        error: 'Invalid CSRF token'
      })
    }

    next()
  }
}

/**
 * Get the current CSRF token for the request
 */
export function getCsrfToken (req: Request): string | undefined {
  return req.cookies[CSRF_COOKIE_NAME]
}
