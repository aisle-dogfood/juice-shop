/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import config from 'config'
import { retrieveAppConfiguration } from '../../routes/appConfiguration'
const expect = chai.expect
chai.use(sinonChai)

describe('appConfiguration', () => {
  let req: any
  let res: any

  it('should return filtered configuration object', () => {
    req = {}
    res = { json: sinon.spy() }

    retrieveAppConfiguration()(req, res)
    
    // Verify the response was called
    expect(res.json).to.have.been.calledOnce
    
    // Verify it returns a config object with filtered data
    const response = res.json.getCall(0).args[0]
    expect(response).to.have.property('config')
    expect(response.config).to.have.property('application')
    
    // Verify it includes safe fields
    expect(response.config.application).to.have.property('name')
    expect(response.config.application).to.have.property('theme')
    
    // Verify it does NOT include sensitive fields like server config
    expect(response.config).to.not.have.property('server')
  })
})
