/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import { Readable } from 'node:stream'
import { finished } from 'node:stream/promises'
import { type Request, type Response, type NextFunction } from 'express'

import * as security from '../lib/insecurity'
import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
import logger from '../lib/logger'

/**
 * Validates if a URL is safe to fetch (not pointing to internal resources).
 * Blocks localhost, loopback addresses, link-local, and private IP ranges.
 * @param urlString The URL to validate
 * @returns true if URL is safe, false otherwise
 */
function isUrlSafe (urlString: string): boolean {
  let parsedUrl: URL
  
  try {
    parsedUrl = new URL(urlString)
  } catch {
    return false
  }

  // Only allow http and https protocols
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    return false
  }

  const hostname = parsedUrl.hostname.toLowerCase()

  // Block localhost and common localhost aliases
  const localhostPatterns = [
    'localhost',
    'localhost.localdomain',
    '0.0.0.0',
    '0000:0000:0000:0000:0000:0000:0000:0000',
    '0:0:0:0:0:0:0:0',
    '::',
    '::1'
  ]
  
  if (localhostPatterns.includes(hostname)) {
    return false
  }

  // Check if hostname is an IPv4 address
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/
  if (ipv4Regex.test(hostname)) {
    const parts = hostname.split('.').map(Number)
    
    // Validate each octet is in valid range
    if (parts.some(part => part < 0 || part > 255)) {
      return false
    }

    // Block private IPv4 ranges
    // 10.0.0.0/8
    if (parts[0] === 10) {
      return false
    }
    
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) {
      return false
    }
    
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) {
      return false
    }
    
    // 127.0.0.0/8 (loopback)
    if (parts[0] === 127) {
      return false
    }
    
    // 169.254.0.0/16 (link-local)
    if (parts[0] === 169 && parts[1] === 254) {
      return false
    }
    
    // 0.0.0.0/8 (current network)
    if (parts[0] === 0) {
      return false
    }
  }

  // Check if hostname is an IPv6 address (enclosed in brackets in URL)
  // Block common private/local IPv6 ranges
  if (hostname.includes(':')) {
    const ipv6Lower = hostname.toLowerCase()
    
    // Block link-local addresses (fe80::/10)
    if (ipv6Lower.startsWith('fe80:') || ipv6Lower.startsWith('fe8') || 
        ipv6Lower.startsWith('fe9') || ipv6Lower.startsWith('fea') || 
        ipv6Lower.startsWith('feb')) {
      return false
    }
    
    // Block unique local addresses (fc00::/7)
    if (ipv6Lower.startsWith('fc') || ipv6Lower.startsWith('fd')) {
      return false
    }
    
    // Block multicast (ff00::/8)
    if (ipv6Lower.startsWith('ff')) {
      return false
    }
  }

  return true
}

export function profileImageUrlUpload () {
  return async (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
      const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
      if (loggedInUser) {
        // Validate URL safety before fetching
        if (!isUrlSafe(url)) {
          logger.warn(`Blocked potentially unsafe URL: ${url}`)
          next(new Error('Invalid or unsafe URL provided'))
          return
        }
        
        try {
          const response = await fetch(url)
          if (!response.ok || !response.body) {
            throw new Error('url returned a non-OK status code or an empty body')
          }
          
          // Validate content type to ensure it's an image
          const contentType = response.headers.get('content-type')
          const validImageTypes = ['image/jpeg', 'image/jpg', 'image/png', 'image/svg+xml', 'image/gif']
          if (contentType && !validImageTypes.some(type => contentType.toLowerCase().includes(type))) {
            throw new Error('URL does not point to a valid image')
          }
          
          const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
          const fileStream = fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`, { flags: 'w' })
          
          // Set a timeout and size limit for the download
          const maxSize = 5 * 1024 * 1024 // 5MB
          let downloadedSize = 0
          
          const reader = response.body.getReader()
          const chunks: Uint8Array[] = []
          
          try {
            while (true) {
              const { done, value } = await reader.read()
              if (done) break
              
              downloadedSize += value.length
              if (downloadedSize > maxSize) {
                throw new Error('Image file too large')
              }
              chunks.push(value)
            }
          } finally {
            reader.releaseLock()
          }
          
          // Write chunks to file
          for (const chunk of chunks) {
            fileStream.write(chunk)
          }
          fileStream.end()
          
          await new Promise<void>((resolve, reject) => {
            fileStream.on('finish', resolve)
            fileStream.on('error', reject)
          })
          
          await UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
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
