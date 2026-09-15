/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

export function serveLogFiles () {
  return (req: Request, res: Response, next: NextFunction) => {
    const file = req.params.file as string

    // Basic sanity checks: no path separators or traversal patterns and only safe characters
    if (!file || file.includes('/') || file.includes('\\') || file.includes('..') || file.startsWith('.')) {
      res.status(403)
      next(new Error('Invalid file name!'))
      return
    }

    const safeFileName = path.basename(file)
    if (safeFileName !== file || !/^[\w\-.]+$/.test(file)) {
      res.status(403)
      next(new Error('Invalid file name!'))
      return
    }

    const logsDir = path.resolve('logs')
    const resolvedPath = path.resolve(logsDir, file)
    const relative = path.relative(logsDir, resolvedPath)
    if (relative.startsWith('..') || path.isAbsolute(relative)) {
      res.status(403)
      next(new Error('Access denied'))
      return
    }

    fs.stat(resolvedPath, (err, stats) => {
      if (err || !stats.isFile()) {
        res.status(404)
        next(new Error('File not found'))
        return
      }
      res.sendFile(resolvedPath, { dotfiles: 'deny' }, (err) => {
        if (err) next(err)
      })
    })
  }
}
