/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import config from 'config'
import { type Request, type Response } from 'express'

export function retrieveAppConfiguration () {
  return (_req: Request, res: Response) => {
    // Return only non-sensitive, client-facing configuration
    // Exclude server configuration (port, baseUrl), credentials, OAuth secrets, 
    // database config, and other sensitive internal data
    const safeConfig = {
      application: {
        domain: config.get('application.domain'),
        name: config.get('application.name'),
        logo: config.get('application.logo'),
        favicon: config.get('application.favicon'),
        theme: config.get('application.theme'),
        showVersionNumber: config.get('application.showVersionNumber'),
        showGitHubLinks: config.get('application.showGitHubLinks'),
        localBackupEnabled: config.get('application.localBackupEnabled'),
        numberOfRandomFakeUsers: config.get('application.numberOfRandomFakeUsers'),
        altcoinName: config.get('application.altcoinName'),
        privacyContactEmail: config.get('application.privacyContactEmail'),
        chatBot: config.get('application.chatBot'),
        social: config.get('application.social'),
        recyclePage: config.get('application.recyclePage'),
        welcomeBanner: config.get('application.welcomeBanner'),
        cookieConsent: config.get('application.cookieConsent'),
        securityTxt: config.get('application.securityTxt'),
        promotion: config.get('application.promotion'),
        easterEggPlanet: config.get('application.easterEggPlanet')
      },
      hackingInstructor: config.has('hackingInstructor') ? config.get('hackingInstructor') : {},
      challenges: config.has('challenges') ? config.get('challenges') : {},
      products: config.has('products') ? config.get('products') : [],
      memories: config.has('memories') ? config.get('memories') : [],
      ctf: config.has('ctf') ? config.get('ctf') : {}
    }
    res.json({ config: safeConfig })
  }
}
