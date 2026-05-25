/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import sinon from 'sinon'
import chai from 'chai'
import sinonChai from 'sinon-chai'
import { serveKeyFiles } from '../../routes/keyServer'
const expect = chai.expect
chai.use(sinonChai)

describe('keyServer', () => {
  let req: any
  let res: any
  let next: any

  beforeEach(() => {
    req = { params: { } }
    res = { sendFile: sinon.spy(), status: sinon.spy() }
    next = sinon.spy()
  })

  it('should serve requested file from folder /encryptionkeys', () => {
    req.params.file = 'test.file'

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.been.calledWith(sinon.match(/encryptionkeys[/\\]test.file/))
  })

  it('should raise error for slashes in filename', () => {
    req.params.file = '../../../../nice.try'

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for path traversal with dot-dot sequences', () => {
    req.params.file = '..%2f..%2f..%2fetc%2fpasswd'

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for backslashes in filename', () => {
    req.params.file = '..\\..\\..\\windows\\system32\\config\\sam'

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for invalid file parameter', () => {
    req.params.file = null

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(400)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })

  it('should raise error for undefined file parameter', () => {
    req.params.file = undefined

    serveKeyFiles()(req, res, next)

    expect(res.sendFile).to.have.not.been.calledWith(sinon.match.any)
    expect(res.status).to.have.been.calledWith(400)
    expect(next).to.have.been.calledWith(sinon.match.instanceOf(Error))
  })
})
