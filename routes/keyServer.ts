/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveKeyFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Resolve the base directory to an absolute path
    const baseDir = path.resolve('encryptionkeys/')
    
    // Join and resolve the requested file path
    const requestedPath = path.resolve(baseDir, file)
    
    // Verify the resolved path is within the base directory to prevent path traversal
    if (requestedPath.startsWith(baseDir + path.sep) || requestedPath === baseDir) {
      res.sendFile(requestedPath)
    } else {
      res.status(403)
      next(new Error('Access denied'))
    }
  }
}
