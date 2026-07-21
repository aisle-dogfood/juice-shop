/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import * as utils from '../utils'
import { Server } from 'socket.io'
import logger from '../logger'
import { notifications, challenges } from '../../data/datacache'
import * as challengeUtils from '../challengeUtils'
import * as security from '../insecurity'

let firstConnectedSocket: any = null

const globalWithSocketIO = global as typeof globalThis & {
  socketIoServer?: Server
}

const registerWebsocketEvents = (server: any) => {
  const io = new Server(server, { cors: { origin: 'http://localhost:4200' } })
  globalWithSocketIO.socketIoServer = io

  // Defensive: ensure unexpected Engine.IO / Socket.IO errors don't crash the whole Node process
  io.engine.on('error', (error: unknown) => {
    logger.warn('Socket.IO engine error: ' + utils.getErrorMessage(error))
  })
  io.engine.on('connection_error', (error: any) => {
    // Engine.IO provides useful context on connection errors (e.g. invalid packets)
    logger.warn('Socket.IO connection error: ' + (error?.message ?? utils.getErrorMessage(error)))
  })

  io.on('connection', (socket: any) => {
    socket.on('error', (error: unknown) => {
      logger.warn('Socket.IO socket error: ' + utils.getErrorMessage(error))
    })
    socket.conn?.on?.('error', (error: unknown) => {
      logger.warn('Socket.IO transport error: ' + utils.getErrorMessage(error))
    })

    if (firstConnectedSocket === null) {
      socket.emit('server started')
      firstConnectedSocket = socket.id
    }

    notifications.forEach((notification: any) => {
      socket.emit('challenge solved', notification)
    })

    socket.on('notification received', (data: any) => {
      const i = notifications.findIndex(({ flag }: any) => flag === data)
      if (i > -1) {
        notifications.splice(i, 1)
      }
    })

    socket.on('verifyLocalXssChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.localXssChallenge, () => { return utils.contains(data, '<iframe src="javascript:alert(`xss`)">') })
      challengeUtils.solveIf(challenges.xssBonusChallenge, () => { return utils.contains(data, config.get('challenges.xssBonusPayload')) })
    })

    socket.on('verifySvgInjectionChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.svgInjectionChallenge, () => { return data?.match(/.*\.\.\/\.\.\/\.\.[\w/-]*?\/redirect\?to=https?:\/\/placecats.com\/(g\/)?[\d]+\/[\d]+.*/) && security.isRedirectAllowed(data) })
    })

    socket.on('verifyCloseNotificationsChallenge', (data: any) => {
      challengeUtils.solveIf(challenges.closeNotificationsChallenge, () => { return Array.isArray(data) && data.length > 1 })
    })
  })
}

export default registerWebsocketEvents
