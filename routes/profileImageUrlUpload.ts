/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable, Transform } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

// Maximum allowed file size for profile image downloads (5MB)
const MAX_FILE_SIZE = 5 * 1024 * 1024

// Timeout for fetch operation (10 seconds)
const FETCH_TIMEOUT = 10000

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
        const filePath = `frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`
        
        try {
          // Create abort controller for timeout
          const abortController = new AbortController()
          const timeoutId = setTimeout(() => abortController.abort(), FETCH_TIMEOUT)
          
          try {
            const response = await fetch(url, { signal: abortController.signal })
            clearTimeout(timeoutId)
            
            if (!response.ok || !response.body) {
              throw new Error('url returned a non-OK status code or an empty body')
            }
            
            // Check Content-Length header if available
            const contentLength = response.headers.get('content-length')
            if (contentLength && parseInt(contentLength) > MAX_FILE_SIZE) {
              throw new Error(`File size exceeds maximum allowed size of ${MAX_FILE_SIZE} bytes`)
            }
            
            // Create a transform stream to track and limit downloaded bytes
            let bytesDownloaded = 0
            const sizeLimitTransform = new Transform({
              transform (chunk, encoding, callback) {
                bytesDownloaded += chunk.length
                if (bytesDownloaded > MAX_FILE_SIZE) {
                  callback(new Error(`File size exceeds maximum allowed size of ${MAX_FILE_SIZE} bytes`))
                } else {
                  callback(null, chunk)
                }
              }
            })
            
            const fileStream = fs.createWriteStream(filePath, { flags: 'w' })
            
            // Pipe with size limit enforcement
            await finished(Readable.fromWeb(response.body as any).pipe(sizeLimitTransform).pipe(fileStream))
            
            await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
          } catch (fetchError) {
            clearTimeout(timeoutId)
            // Clean up the file if it was partially written
            try {
              await fs.promises.unlink(filePath)
            } catch (unlinkError) {
              // File might not exist, ignore the error
            }
            throw fetchError
          }
        } catch (error) {
          try {
            const user = await UserModel.findByPk(loggedInUser.data.id)
            await user?.update({ profileImage: url })
            logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(error)}; using image link directly`)
          } catch (error) {
            next(error)
            return
          }
        }
      } else {
        next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        return
      }
    }
    res.location(process.env.BASE_PATH + '/profile')
    res.redirect(process.env.BASE_PATH + '/profile')
  }
}
