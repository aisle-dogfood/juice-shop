/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file || typeof file !== 'string') {
      res.status(400)
      next(new Error('Invalid file parameter!'))
      return
    }

    // Sanitize the filename to remove/replace unsafe characters
    const sanitizedFile = security.sanitizeFilename(file)
    
    // Construct the full path and normalize it
    const basePath = path.resolve('encryptionkeys/')
    const requestedPath = path.resolve(basePath, sanitizedFile)
    
    // Ensure the resolved path is still within the encryptionkeys directory
    const normalizedBasePath = path.normalize(basePath + path.sep)
    const normalizedRequestedPath = path.normalize(requestedPath + path.sep)
    
    if (!normalizedRequestedPath.startsWith(normalizedBasePath)) {
      res.status(403)
      next(new Error('Access denied: path traversal attempt detected!'))
      return
    }

    // Additional check for any remaining path traversal patterns
    if (sanitizedFile.includes('..') || sanitizedFile.includes('/') || sanitizedFile.includes('\\')) {
      res.status(403)
      next(new Error('File names cannot contain path traversal characters!'))
      return
    }

    res.sendFile(requestedPath)
  }
}
