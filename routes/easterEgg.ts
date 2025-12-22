/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response } from 'express'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

export function serveEasterEgg () {
  return (req: Request, res: Response) => {
    challengeUtils.solveIf(challenges.easterEggLevelTwoChallenge, () => { return true })
    
    // Apply strict Content Security Policy for the easter egg page
    const CSP = "default-src 'self'; script-src 'self'; img-src 'self'; style-src 'unsafe-inline'; object-src 'none'; base-uri 'self'; form-action 'self'"
    res.set({
      'Content-Security-Policy': CSP
    })
    
    res.sendFile(path.resolve('frontend/dist/frontend/assets/private/threejs-demo.html'))
  }
}
