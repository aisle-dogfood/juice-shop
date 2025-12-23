/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as frisby from 'frisby'
import * as utils from '../../lib/utils'
import { expect } from '@jest/globals'

const Joi = frisby.Joi

const REST_URL = 'http://localhost:3000/rest/admin'

describe('/rest/admin/application-version', () => {
  it('GET application version from package.json', () => {
    return frisby.get(REST_URL + '/application-version')
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('json', {
        version: utils.version()
      })
  })
})

describe('/rest/admin/application-configuration', () => {
  it('GET filtered application configuration', () => {
    return frisby.get(REST_URL + '/application-configuration')
      .expect('status', 200)
      .expect('header', 'content-type', /application\/json/)
      .expect('jsonTypes', {
        config: Joi.object()
      })
      .then((res: any) => {
        // Verify sensitive server configuration is not exposed
        expect(res.json.config).to.not.have.property('server')
      })
  })
})
