/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import * as security from '../lib/insecurity'

export function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    if (!file.includes('/')) {
      // Sanitize the filename to prevent path traversal
      const sanitizedFile = security.sanitizeFilename(security.cutOffPoisonNullByte(file))
      
      // Resolve the full paths
      const quarantineDir = path.resolve('ftp/quarantine/')
      const requestedPath = path.resolve(quarantineDir, sanitizedFile)
      
      // Validate that the resolved path is still within the quarantine directory
      if (requestedPath.startsWith(quarantineDir + path.sep) || requestedPath === quarantineDir) {
        res.sendFile(requestedPath)
      } else {
        res.status(403)
        next(new Error('Invalid file path!'))
      }
    } else {
      res.status(403)
      next(new Error('File names cannot contain forward slashes!'))
    }
  }
}
