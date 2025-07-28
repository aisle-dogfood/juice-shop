/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import { RecycleModel } from '../models/recycle'
import * as utils from '../lib/utils'
import { sanitizeHtml } from '../lib/insecurity'

export const getRecycleItem = () => (req: Request, res: Response) => {
  RecycleModel.findAll({
    where: {
      id: JSON.parse(req.params.id)
    }
  }).then((Recycle) => {
    // Sanitize the data to prevent XSS attacks
    const sanitizedRecycle = Recycle.map(item => {
      const plainItem = item.get({ plain: true })
      // Sanitize string fields that might contain user input
      if (plainItem.date && typeof plainItem.date === 'string') {
        plainItem.date = sanitizeHtml(plainItem.date)
      }
      return plainItem
    })
    return res.send(utils.queryResultToJson(sanitizedRecycle))
  }).catch((_: unknown) => {
    return res.send('Error fetching recycled items. Please try again')
  })
}

export const blockRecycleItems = () => (req: Request, res: Response) => {
  const errMsg = { err: 'Sorry, this endpoint is not supported.' }
  return res.send(utils.queryResultToJson(errMsg))
}
