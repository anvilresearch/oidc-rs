/**
 * Test dependencies
 */
const path = require('path')
const chai = require('chai')
const sinon = require('sinon')
const HttpMocks = require('node-mocks-http')

/**
 * Assertions
 */
chai.use(require('sinon-chai'))
chai.use(require('dirty-chai'))
chai.use(require('chai-as-promised'))
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const AuthenticatedRequest = require('../src/AuthenticatedRequest')
const ResourceServer = require('../src/ResourceServer')

/**
 * Tests
 */
describe('AuthenticatedRequest', () => {
  // let request = new AuthenticatedRequest(rs, req, res, next, options)

  describe('constructor', () => {
    it('should set rs')
    it('should set req')
    it('should set res')
    it('should set next')
    it('should set options')
  })

  describe('authenticate', () => {})

  describe('validateAuthorizationHeader', () => {
    let rs, req, res, next, options, request

    beforeEach(() => {
      rs = new ResourceServer({})
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
      next = () => {}
      options = {}
      request = new AuthenticatedRequest(rs, req, res, next, options)
      sinon.spy(request, 'badRequest')
    })

    describe('with multiple authentication methods', () => {
      it('should respond with "Bad Request"', () => {
        request.req.headers = { authorization: 'Bearer 1234' }
        request.token = '1234'

        expect(() => request.validateAuthorizationHeader(request))
          .to.throw(/Multiple authentication methods/)

        expect(request.badRequest)
          .to.have.been.calledWith('Multiple authentication methods')
      })
    })

    describe('with invalid authorization header', () => {
      it('should respond with "Bad Request"', () => {
        request.req.headers = { authorization: 'Bearer' }

        expect(() => request.validateAuthorizationHeader(request))
          .to.throw(/Invalid authorization header/)

        expect(request.badRequest)
          .to.have.been.calledWith('Invalid authorization header')
      })
    })

    describe('with invalid authorization scheme', () => {
      it('should respond with "Bad Request"', () => {
        request.req.headers = { authorization: 'Something 1234' }

        expect(() => request.validateAuthorizationHeader(request))
          .to.throw(/Invalid authorization scheme/)

        expect(request.badRequest)
          .to.have.been.calledWith('Invalid authorization scheme')
      })
    })

    describe('with well-formed authorization header', () => {
      it('should return its argument')

      it('should set request token', () => {
        request.req.headers = { authorization: 'Bearer 1234' }

        let returnedRequest = request.validateAuthorizationHeader(request)

        expect(returnedRequest.token).to.equal('1234')
      })
    })
  })

  describe('validateQueryParameter', () => {
    describe('with default disabled query option', () => {
      it('should reject undefined value')
      it('should respond with "Bad Request"')
    })

    describe('with multiple authentication methods', () => {
      it('should reject undefined value')
      it('should respond with "Bad Request"')
    })

    describe('with well-formed and enabled query "access_token" parameter', () => {
      it('should return its argument')
      it('should set request token')
    })
  })

  describe('validateBodyParameter', () => {
    describe('with multiple authentication methods', () => {
      it('should reject undefined value')
      it('should respond with "Bad Request"')
    })

    describe('with invalid "Content-Type" header', () => {
      it('should reject undefined value')
      it('should respond with "Bad Request"')
    })

    describe('with well-formed body "access_token" parameter', () => {
      it('should return its argument')
      it('should set request token')
    })
  })

  describe('requireAccessToken', () => {
    let rs, req, res, next, options, request

    beforeEach(() => {
      rs = new ResourceServer({})
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
      next = () => {}
      options = {}
      request = new AuthenticatedRequest(rs, req, res, next, options)

      sinon.spy(request, 'unauthorized')
    })

    describe('with mandatory authentication and missing bearer token', () => {
      it('should respond with "Unauthorized', () => {
        // By default: request.options.optional = false
        // request has no token set

        expect(() => request.requireAccessToken(request))
          .to.throw(/Unauthorized/)

        expect(request.unauthorized).to.have.been.called()
      })
    })

    describe('with optional authentication and absent bearer token', () => {
      it('should return its argument', () => {
        request.options.optional = true

        let returnedRequest = request.requireAccessToken(request)

        expect(returnedRequest).to.equal(request)
      })

      it('should succeed the process')
    })

    describe('with token present', () => {
      it('should return its argument', () => {
        request.token = '1234'

        let returnedRequest = request.requireAccessToken(request)

        expect(returnedRequest).to.equal(request)
      })
    })
  })

  describe('validateAccessToken', () => {

  })

  describe('decode', () => {
    describe('with undecodable JWT token', () => {
      it('should reject undefined value')
      it('should respond with "Unauthorized')
    })

    describe('with invalid JWT contents', () => {
      it('should reject undefined value')
      it('should respond with "Unauthorized')
    })

    describe('with decodable token', () => {
      it('should return its argument')
      it('should set request jwt')
    })
  })

  describe('allow', () => {
    describe('with configured issuers and unknown issuer', () => {
      it('should reject undefined value')
      it('should respond with "Forbidden')
    })

    describe('with configured audience and unknown client', () => {
      it('should reject undefined value')
      it('should respond with "Forbidden')
    })

    describe('with configured subjects and unknown subject', () => {
      it('should reject undefined value')
      it('should respond with "Forbidden')
    })

    describe('with permitted request', () => {
      it('should return its argument')
    })
  })

  describe('deny', () => {
    describe('with configured issuers and matching issuer', () => {
      it('should reject undefined value')
      it('should respond with "Forbidden')
    })

    describe('with configured audience and matching client', () => {
      it('should reject undefined value')
      it('should respond with "Forbidden')
    })

    describe('with configured subjects and matching subject', () => {
      it('should reject undefined value')
      it('should respond with "Forbidden')
    })

    describe('with permitted request', () => {
      it('should return its argument')
    })
  })

  describe('resolveKeys', () => {

  })

  describe('verifySignature', () => {
    describe('with invalid signature', () => {
      it('should reject undefined value')
      it('should respond with "Unauthorized')
    })

    describe('with verified signature', () => {
      it('should resolve its argument')
    })
  })

  describe('validateExpiry', () => {
    describe('with expired token', () => {
      it('should reject undefined value')
      it('should respond with "Unauthorized')
    })

    describe('with valid exp', () => {
      it('should resolve its argument')
    })
  })

  describe('validateNotBefore', () => {
    describe('with future valid token', () => {
      it('should reject undefined value')
      it('should respond with "Unauthorized')
    })

    describe('with valid nbf', () => {
      it('should resolve its argument')
    })
  })

  describe('validateScope', () => {
    describe('with insufficient scope', () => {
      it('should reject undefined value')
      it('should respond with "Forbidden')
    })

    describe('with sufficient scope', () => {
      it('should resolve its argument')
    })
  })

  describe('success', () => {
    it('should pass control to next middleware')
  })

  describe('badRequest', () => {
    it('should reject undefined')
    it('should respond 400')
    it('should respond JSON')
    it('should respond with error')
    it('should respond with error description')
  })

  describe('unauthorized', () => {
    it('should reject undefined')
    it('should respond 401')
    it('should respond "Unauthorized"')
    it('should set WWW-Authenticate challenge')
    it('should set WWW-Authenticate challenge scheme')
  })

  describe('forbidden', () => {
    it('should reject undefined')
    it('should respond 403')
    it('should respond "Forbidden"')
    it('should set WWW-Authenticate challenge')
    it('should set WWW-Authenticate challenge scheme')
  })

  describe('internalServerError', () => {
    it('should respond 500')
    it('should respond "Internal Server Error"')
  })

  describe('encodeChallengeParams', () => {
    it('should separate keys and values with "="')
    it('should separate parameters with ", "')
  })
})
