/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import './testJwtKeySetup'
import * as server from '../server'

export default async () => {
  await server.start()
}
