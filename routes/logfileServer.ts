/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Resolve the base logs directory to an absolute path
    const logsDir = path.resolve('logs/')
    
    // Resolve the requested file path
    const requestedPath = path.resolve(logsDir, file)
    
    // Validate that the resolved path is within the logs directory
    // This prevents path traversal attacks using ../ or other techniques
    if (!requestedPath.startsWith(logsDir + path.sep)) {
      res.status(403)
      next(new Error('Access denied: Invalid file path'))
    } else {
      res.sendFile(requestedPath)
    }
  }
}
