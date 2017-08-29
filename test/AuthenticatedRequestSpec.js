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
const Credential = require('../src/Credential')

/**
 * Tests
 */
describe('AuthenticatedRequest', () => {
  let req, res, request
  let rs = new ResourceServer({})
  let options = {}
  let next = () => {}
  const realm = 'https://example.com'

  describe('constructor', () => {
    req = {}
    res = {}

    beforeEach(() => {
      request = new AuthenticatedRequest(rs, req, res, next, options)
    })

    it('should set rs', () => {
      expect(request.rs).to.equal(rs)
    })

    it('should set req', () => {
      expect(request.req).to.equal(req)
    })

    it('should set res', () => {
      expect(request.res).to.equal(res)
    })

    it('should set next', () => {
      expect(request.next).to.equal(next)
    })

    it('should set options', () => {
      expect(request.options).to.equal(options)
    })
  })

  describe('authenticate', () => {})

  describe('validateAuthorizationHeader', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
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
      it('should return its argument', () => {
        request.req.headers = { authorization: 'Bearer 1234' }

        let returnedRequest = request.validateAuthorizationHeader(request)

        expect(returnedRequest).to.equal(request)
      })

      it('should set request token', () => {
        request.req.headers = { authorization: 'Bearer 1234' }

        let returnedRequest = request.validateAuthorizationHeader(request)

        expect(returnedRequest.token).to.equal('1234')
      })
    })
  })

  describe('validateQueryParameter', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest({ query: { access_token: 't0ken' } })
      res = HttpMocks.createResponse()
      options = { query: true }
      request = new AuthenticatedRequest(rs, req, res, next, options)
      sinon.spy(request, 'badRequest')
    })

    describe('with default disabled query option', () => {
      it('should throw an invalid authentication method error', () => {
        request.options.query = undefined

        expect(() => request.validateQueryParameter(request))
          .to.throw(/Invalid authentication method/)
      })

      it('should throw via "Bad Request"', () => {
        request.options.query = undefined

        try {
          request.validateQueryParameter(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.badRequest).to.have.been.called()
        }
      })
    })

    describe('with multiple authentication methods', () => {
      it('should throw a multiple authentication methods error', () => {
        request.token = 't0ken2'

        expect(() => request.validateQueryParameter(request))
          .to.throw(/Multiple authentication methods/)
      })

      it('should throw via "Bad Request"', () => {
        request.token = 't0ken2'

        try {
          request.validateQueryParameter(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.badRequest).to.have.been.called()
        }
      })
    })

    describe('with a previously validated and enabled query "access_token" parameter', () => {
      it('should return its argument', () => {
        let response = request.validateQueryParameter(request)
        expect(response).to.equal(request)
      })

      it('should set request token', () => {
        let response = request.validateQueryParameter(request)
        expect(response.token).to.equal('t0ken')
      })
    })
  })

  describe('validateBodyParameter', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest({
        body: { access_token: 't0ken' },
        headers: { 'content-type': 'application/x-www-form-urlencoded' }
      })
      res = HttpMocks.createResponse()
      request = new AuthenticatedRequest(rs, req, res, next, options)
      sinon.spy(request, 'badRequest')
    })

    describe('with multiple authentication methods', () => {
      it('should throw a multiple auth methods error', () => {
        request.token = 't0ken2'

        expect(() => request.validateBodyParameter(request))
          .to.throw(/Multiple authentication methods/)
      })

      it('should throw via "Bad Request"', () => {
        request.token = 't0ken2'

        try {
          request.validateBodyParameter(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.badRequest).to.have.been.called()
        }
      })
    })

    describe('with invalid "Content-Type" header', () => {
      it('should throw an Invalid Content-Type error', () => {
        request.req.headers['content-type'] = 'text/plain'

        expect(() => request.validateBodyParameter(request))
          .to.throw(/Invalid Content-Type/)
      })

      it('should throw via "Bad Request"', () => {
        request.req.headers['content-type'] = 'text/plain'

        try {
          request.validateBodyParameter(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.badRequest).to.have.been.called()
        }
      })
    })

    describe('with well-formed body "access_token" parameter', () => {
      it('should return its argument', () => {
        let result = request.validateBodyParameter(request)

        expect(result).to.equal(request)
      })

      it('should set request token', () => {
        let result = request.validateBodyParameter(request)

        expect(result.token).to.equal('t0ken')
      })
    })
  })

  describe('requireAccessToken', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
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
    it('should return request if optional auth and no token', () => {
      req = {}
      res = {}
      let options = { optional: true }

      request = new AuthenticatedRequest(rs, req, res, next, options)

      return request.validateAccessToken(request)
        .then((result) => {
          expect(result).to.equal(request)
        })
    })
  })

  describe('decode', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
      options = { realm: 'https://example.com' }
      request = new AuthenticatedRequest(rs, req, res, next, options)

      sinon.spy(request, 'unauthorized')
    })

    describe('with undecodable JWT token', () => {
      it('should throw an error', done => {
        request.token = 'invalid t0ken'

        try {
          request.decode(request)
        } catch (err) {
          expect(err.message).to.equal('Unauthorized')
          expect(err.error_description).to.equal('Access token is not a JWT')
          done()
        }
      })

      it('should throw via "Unauthorized"', done => {
        request.token = 'invalid t0ken'

        try {
          request.decode(request)
        } catch (err) {
          expect(request.unauthorized).to.have.been.called()
          done()
        }
      })
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
    beforeEach(() => {
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
      options = {
        realm,
        allow: {
          issuers: [ 'issuer1', 'issuer2' ],
          audience: [ 'aud1', 'aud2' ],
          subjects: [ 'subj1', 'subj2' ]
        }
      }
      request = new AuthenticatedRequest(rs, req, res, next, options)
      request.credential = Credential.from({
        payload: {
          iss: 'issuer1', aud: 'aud1', sub: 'subj1'
        }
      })

      sinon.spy(request, 'forbidden')
    })

    describe('with allow not defined in options', () => {
      it('should return its argument', () => {
        request.options.allow = undefined
        request.credential.jwt.payload = {}

        let result = request.allow(request)

        expect(result).to.equal(request)
      })
    })

    describe('with configured issuers and unknown issuer', () => {
      it('should throw an error', done => {
        request.credential.jwt.payload.iss = 'some-issuer'

        try {
          request.allow(request)
        } catch (err) {
          expect(err.message).to.equal('Forbidden')
          expect(err.statusCode).to.equal(403)
          expect(err.realm).to.equal(realm)
          done()
        }
      })

      it('should throw via "Forbidden', done => {
        request.credential.jwt.payload.iss = 'some-issuer'

        try {
          request.allow(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.forbidden).to.have.been.called()
          done()
        }
      })
    })

    describe('with configured audience and unknown client', () => {
      it('should throw an error', done => {
        request.credential.jwt.payload.aud = 'some-client'

        try {
          request.allow(request)
        } catch (err) {
          expect(err.message).to.equal('Forbidden')
          expect(err.statusCode).to.equal(403)
          expect(err.realm).to.equal(realm)
          done()
        }
      })

      it('should throw via "Forbidden', done => {
        request.credential.jwt.payload.aud = 'some-client'

        try {
          request.allow(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.forbidden).to.have.been.called()
          done()
        }
      })
    })

    describe('with configured audience filter function', () => {
      it('should pass if the filter function passes', () => {
        const audienceFilter = (aud) => {
          return aud === 'aud1'
        }
        options = {
          realm,
          allow: {
            audience: audienceFilter,
          }
        }
        request = new AuthenticatedRequest(rs, req, res, next, options)
        request.credential = Credential.from({
          payload: {
            iss: 'issuer1', aud: 'aud1', sub: 'subj1'
          }
        })
        sinon.spy(request, 'forbidden')

        request.allow(request)

        expect(request.forbidden).to.not.have.been.called()
      })

      it('should fail if the filter function fails', done => {
        const audienceFilter = () => { return false }
        options = {
          realm,
          allow: {
            audience: audienceFilter,
          }
        }
        request = new AuthenticatedRequest(rs, req, res, next, options)
        request.credential = Credential.from({
          payload: {
            iss: 'issuer1', aud: 'aud1', sub: 'subj1'
          }
        })
        sinon.spy(request, 'forbidden')

        try {
          request.allow(request)
        } catch (err) {
          expect(err.message).to.equal('Forbidden')
          expect(err.statusCode).to.equal(403)
          expect(err.error).to.equal('access_denied')
          expect(err.error_description).to.equal('Token does not pass the audience allow filter')
          expect(err.realm).to.equal(realm)
          done()
        }
      })
    })

    describe('with configured issuer filter function', () => {
      it('should pass if the filter function passes', () => {
        const issuerFilter = (iss) => {
          return iss === 'issuer1'
        }
        options = {
          realm,
          allow: {
            issuers: issuerFilter,
          }
        }
        request = new AuthenticatedRequest(rs, req, res, next, options)
        request.credential = Credential.from({
          payload: {
            iss: 'issuer1', aud: 'aud1', sub: 'subj1'
          }
        })
        sinon.spy(request, 'forbidden')

        request.allow(request)

        expect(request.forbidden).to.not.have.been.called()
      })

      it('should fail if the filter function fails', done => {
        const issuerFilter = () => { return false }
        options = {
          realm,
          allow: {
            issuers: issuerFilter,
          }
        }
        request = new AuthenticatedRequest(rs, req, res, next, options)
        request.credential = Credential.from({
          payload: {
            iss: 'issuer1', aud: 'aud1', sub: 'subj1'
          }
        })
        sinon.spy(request, 'forbidden')

        try {
          request.allow(request)
        } catch (err) {
          expect(err.message).to.equal('Forbidden')
          expect(err.statusCode).to.equal(403)
          expect(err.error).to.equal('access_denied')
          expect(err.error_description).to.equal('Token does not pass the issuer allow filter')
          expect(err.realm).to.equal(realm)
          done()
        }
      })
    })

    describe('with configured subject filter function', () => {
      it('should pass if the filter function passes', () => {
        const subjectFilter = (sub) => {
          return sub === 'subj1'
        }
        options = {
          realm,
          allow: {
            subjects: subjectFilter,
          }
        }
        request = new AuthenticatedRequest(rs, req, res, next, options)
        request.credential = Credential.from({
          payload: {
            iss: 'issuer1', aud: 'aud1', sub: 'subj1'
          }
        })
        sinon.spy(request, 'forbidden')

        request.allow(request)

        expect(request.forbidden).to.not.have.been.called()
      })

      it('should fail if the filter function fails', done => {
        const subjectFilter = () => { return false }
        options = {
          realm,
          allow: {
            subjects: subjectFilter,
          }
        }
        request = new AuthenticatedRequest(rs, req, res, next, options)
        request.credential = Credential.from({
          payload: {
            iss: 'issuer1', aud: 'aud1', sub: 'subj1'
          }
        })
        sinon.spy(request, 'forbidden')

        try {
          request.allow(request)
        } catch (err) {
          expect(err.message).to.equal('Forbidden')
          expect(err.statusCode).to.equal(403)
          expect(err.error).to.equal('access_denied')
          expect(err.error_description).to.equal('Token does not pass the subject allow filter')
          expect(err.realm).to.equal(realm)
          done()
        }
      })
    })

    describe('with configured subjects and unknown subject', () => {
      it('should throw an error', done => {
        request.credential.jwt.payload.sub = 'some-subject'

        try {
          request.allow(request)
        } catch (err) {
          expect(err.message).to.equal('Forbidden')
          expect(err.statusCode).to.equal(403)
          expect(err.realm).to.equal(realm)
          done()
        }
      })

      it('should throw via "Forbidden', done => {
        request.credential.jwt.payload.sub = 'some-subject'

        try {
          request.allow(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.forbidden).to.have.been.called()
          done()
        }
      })
    })

    describe('with permitted request', () => {
      it('should return its argument', () => {
        let result = request.allow(request)

        expect(result).to.equal(request)
      })
    })
  })

  describe('deny', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
      options = {
        realm,
        deny: {
          issuers: [ 'issuer1', 'issuer2' ],
          audience: [ 'aud1', 'aud2' ],
          subjects: [ 'subj1', 'subj2' ]
        }
      }
      request = new AuthenticatedRequest(rs, req, res, next, options)
      request.credential = Credential.from({ payload: {} })

      sinon.spy(request, 'forbidden')
    })

    describe('with no deny defined in options', () => {
      it('should return its argument', () => {
        request.options.deny = undefined

        let result = request.deny(request)

        expect(result).to.equal(request)
      })
    })

    describe('with configured issuers and matching issuer', () => {
      it('should throw an error', done => {
        request.credential.jwt.payload.iss = 'issuer1'

        try {
          request.deny(request)
        } catch (err) {
          expect(err.message).to.equal('Forbidden')
          expect(err.statusCode).to.equal(403)
          expect(err.realm).to.equal(realm)
          done()
        }
      })

      it('should throw via "Forbidden', done => {
        request.credential.jwt.payload.iss = 'issuer1'

        try {
          request.deny(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.forbidden).to.have.been.called()
          done()
        }
      })
    })

    describe('with configured audience and matching client', () => {
      it('should throw an error', done => {
        request.credential.jwt.payload.aud = 'aud1'

        try {
          request.deny(request)
        } catch (err) {
          expect(err.message).to.equal('Forbidden')
          expect(err.statusCode).to.equal(403)
          expect(err.realm).to.equal(realm)
          done()
        }
      })

      it('should throw via "Forbidden', done => {
        request.credential.jwt.payload.aud = 'aud1'

        try {
          request.deny(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.forbidden).to.have.been.called()
          done()
        }
      })
    })

    describe('with configured subjects and matching subject', () => {
      it('should throw an error', done => {
        request.credential.jwt.payload.sub = 'subj1'

        try {
          request.deny(request)
        } catch (err) {
          expect(err.message).to.equal('Forbidden')
          expect(err.statusCode).to.equal(403)
          expect(err.realm).to.equal(realm)
          done()
        }
      })

      it('should throw via "Forbidden', done => {
        request.credential.jwt.payload.sub = 'subj1'

        try {
          request.deny(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.forbidden).to.have.been.called()
          done()
        }
      })
    })

    describe('with permitted request', () => {
      it('should return its argument', () => {
        request.credential.jwt.payload = {
          iss: 'valid-issuer', aud: 'valid-client', sub: 'valid-subj'
        }

        let result = request.deny(request)

        expect(result).to.equal(request)
      })
    })
  })

  describe('resolveKeys', () => {
    const issuer = 'https://issuer.example.com'
    let provider, providersCache

    beforeEach(() => {
      req = {}
      res = HttpMocks.createResponse()
      options = { realm }
      request = new AuthenticatedRequest(rs, req, res, next, options)

      provider = { jwks: {} }

      request.credential = Credential.from({
        payload: { iss: issuer },
        resolveKeys: sinon.stub().withArgs(provider.jwks).returns(true)
      })

      providersCache = {
        resolve: sinon.stub().withArgs(issuer).resolves(provider),
        rotate: sinon.stub().withArgs(issuer).resolves(provider)
      }
      request.rs.providers = providersCache
      sinon.spy(request, 'unauthorized')
    })

    it('should load provider from provider cache', () => {
      return request.resolveKeys(request)
        .then(() => {
          expect(providersCache.resolve).to.have.been.calledWith(issuer)
        })
    })

    it('should pass the request through if keys resolve', () => {
      return request.resolveKeys(request)
        .then(result => {
          expect(result).to.equal(request)
        })
    })

    it('should rotate provider keys if initially they are not resolved', () => {
      request.credential.jwt.resolveKeys = sinon.stub()
      request.credential.jwt.resolveKeys.onCall(0).returns(false)
      request.credential.jwt.resolveKeys.onCall(1).returns(true)

      return request.resolveKeys(request)
        .then(result => {
          expect(result).to.equal(request)
          expect(providersCache.rotate).to.have.been.calledWith(issuer)
        })
    })

    it('should reject with an error if keys do not resolve', done => {
      request.credential.jwt.resolveKeys = sinon.stub().returns(false)

      request.resolveKeys(request)
        .catch(err => {
          expect(err.statusCode).to.equal(401)
          expect(request.unauthorized).to.have.been.called()
          expect(err.error).to.equal('invalid_token')
          expect(err.error_description).to.equal('Cannot find key to verify JWT signature')
          done()
        })
    })
  })

  describe('verifySignature', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
      options = { realm }
      request = new AuthenticatedRequest(rs, req, res, next, options)
      request.credential = Credential.from({})

      sinon.spy(request, 'unauthorized')
    })

    describe('with invalid signature', () => {
      it('should reject with a 401 error', done => {
        request.credential.verifySignature = sinon.stub().resolves(false)

        request.verifySignature(request)
          .catch(err => {
            expect(err.statusCode).to.equal(401)
            expect(err.realm).to.equal(realm)
            done()
          })
      })

      it('should reject via "Unauthorized', done => {
        request.credential.verifySignature = sinon.stub().resolves(false)

        request.verifySignature(request)
          .catch(err => {
            expect(err).to.exist()
            expect(request.unauthorized).to.have.been.called()
            done()
          })
      })
    })

    describe('with verified signature', () => {
      it('should resolve its argument', () => {
        request.credential.verifySignature = sinon.stub().resolves(true)

        return request.verifySignature(request)
          .then(result => {
            expect(result).to.equal(request)
          })
      })
    })
  })

  describe('validateExpiry', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
      options = { realm }
      request = new AuthenticatedRequest(rs, req, res, next, options)
      request.credential = Credential.from({ payload: {} })

      sinon.spy(request, 'unauthorized')
    })

    describe('with expired token', () => {
      it('should throw a 401 error', done => {
        request.credential.jwt.payload.exp = Math.floor(Date.now() / 1000) - 100

        try {
          request.validateExpiry(request)
        } catch(err) {
          expect(err.statusCode).to.equal(401)
          expect(err.realm).to.equal(realm)
          expect(err.error).to.equal('invalid_token')
          expect(err.error_description).to.equal('Access token is expired')
          done()
        }
      })

      it('should throw via "Unauthorized', done => {
        request.credential.jwt.payload.exp = Math.floor(Date.now() / 1000) - 100

        try {
          request.validateExpiry(request)
        } catch(err) {
          expect(err).to.exist()
          expect(request.unauthorized).to.have.been.called()
          done()
        }
      })
    })

    describe('with valid exp', () => {
      it('should resolve its argument', () => {
        request.credential.jwt.payload.exp = Math.floor(Date.now() / 1000) + 1000

        let result = request.validateExpiry(request)

        expect(result).to.equal(request)
      })
    })
  })

  describe('validateNotBefore', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
      options = { realm }
      request = new AuthenticatedRequest(rs, req, res, next, options)
      request.credential = Credential.from({ payload: {} })

      sinon.spy(request, 'unauthorized')
    })

    describe('with future valid token', () => {
      it('should throw a 401 error', done => {
        request.credential.jwt.payload.nbf = Math.ceil(Date.now() / 1000) + 1000

        try {
          request.validateNotBefore(request)
        } catch (err) {
          expect(err.statusCode).to.equal(401)
          expect(err.realm).to.equal(realm)
          expect(err.error).to.equal('invalid_token')
          expect(err.error_description).to.equal('Access token is not yet active')
          done()
        }
      })

      it('should throw via "Unauthorized', done => {
        request.credential.jwt.payload.nbf = Math.ceil(Date.now() / 1000) + 1000

        try {
          request.validateNotBefore(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.unauthorized).to.have.been.called()
          done()
        }
      })
    })

    describe('with valid nbf', () => {
      it('should return its argument', () => {
        request.credential.jwt.payload.nbf = Math.ceil(Date.now() / 1000) - 1000

        let result = request.validateNotBefore(request)

        expect(result).to.equal(request)
      })
    })
  })

  describe('validateScope', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
      options = {
        realm,
        scopes: ['scope1', 'scope2']
      }

      request = new AuthenticatedRequest(rs, req, res, next, options)
      request.credential = Credential.from({ payload: {} })

      sinon.spy(request, 'forbidden')
    })

    describe('with scopes not configured in the options', () => {
      it('should pass through the request', () => {
        request.options.scopes = undefined

        let result = request.validateScope(request)

        expect(result).to.equal(request)
      })
    })

    describe('with missing scope', () => {
      it('should throw a 403 error', done => {
        try {
          request.validateScope(request)
        } catch (err) {
          expect(err.statusCode).to.equal(403)
          expect(err.realm).to.equal(realm)
          expect(err.error).to.equal('insufficient_scope')
          expect(err.error_description).to.equal('Access token has insufficient scope')
          done()
        }
      })

      it('should throw via "Forbidden', done => {
        try {
          request.validateScope(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.forbidden).to.have.been.called()
          done()
        }
      })
    })

    describe('with partial / insufficient scope', () => {
      it('should throw a 403 error', done => {
        request.credential.jwt.payload.scope = 'scope1'  // one out of two scopes present

        try {
          request.validateScope(request)
        } catch (err) {
          expect(err.statusCode).to.equal(403)
          expect(err.realm).to.equal(realm)
          expect(err.error).to.equal('insufficient_scope')
          expect(err.error_description).to.equal('Access token has insufficient scope')
          done()
        }
      })

      it('should throw via "Forbidden', done => {
        request.credential.jwt.payload.scope = ['scope1']  // one out of two scopes present

        try {
          request.validateScope(request)
        } catch (err) {
          expect(err).to.exist()
          expect(request.forbidden).to.have.been.called()
          done()
        }
      })
    })

    describe('with sufficient scope', () => {
      it('should return its argument', () => {
        request.credential.jwt.payload.scope = 'scope1 scope2'

        let result = request.validateScope(request)

        expect(result).to.equal(request)
      })
    })
  })

  describe('success', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
      next = sinon.stub()
      options = {}

      request = new AuthenticatedRequest(rs, req, res, next, options)
      request.credential = Credential.from({ payload: {} })
    })

    it('should pass control to next middleware', () => {
      request.success(request)

      expect(next).to.have.been.called()
    })
  })

  describe('Error handlers', () => {
    beforeEach(() => {
      req = HttpMocks.createRequest()
      res = HttpMocks.createResponse()
      next = sinon.stub()
      options = {}

      request = new AuthenticatedRequest(rs, req, res, next, options)
      request.jwt = { payload: {} }
    })

    describe('badRequest', () => {
      const errorMessage = 'error message'

      it('should throw a handled error', done => {
        try {
          request.badRequest(errorMessage)
        } catch (err) {
          expect(err.message).to.equal(errorMessage)
          expect(err.handled).to.be.true()
          done()
        }
      })

      it('should respond with 400 status', done => {
        try {
          request.badRequest(errorMessage)
        } catch (err) {
          expect(request.res._getStatusCode()).to.equal(400)

          expect(err.statusCode).to.equal(400)
          done()
        }
      })

      it('should respond with error param', done => {
        try {
          request.badRequest(errorMessage)
        } catch (err) {
          expect(err.error).to.equal('invalid_request')
          done()
        }
      })

      it('should respond with error_description', done => {
        try {
          request.badRequest(errorMessage)
        } catch (err) {
          expect(err.error_description).to.equal(errorMessage)
          done()
        }
      })

      it('should respond with JSON by default', done => {
        try {
          request.badRequest(errorMessage)
        } catch (err) {
          expect(request.res._isJSON()).to.be.true()
          done()
        }
      })

      it('should pass error to next() handler when handleErrors is false', done => {
        request.options.handleErrors = false

        try {
          request.badRequest(errorMessage)
        } catch (err) {
          expect(request.next).to.have.been.calledWith(err)
          done()
        }
      })
    })

    describe('unauthorized', () => {
      const errorMessage = 'unauthorized error message'
      const params = {
        realm,
        scope: 'openid',
        error: 'invalid_token',
        error_description: errorMessage,
        error_uri: 'https://example.com/errors/1'
      }

      it('should throw a handled error', done => {
        try {
          request.unauthorized(params)
        } catch (err) {
          expect(err.handled).to.be.true()
          expect(err.error).to.equal(params.error)
          expect(err.error_description).to.equal(params.error_description)
          expect(err.realm).to.equal(params.realm)
          expect(err.error_uri).to.equal(params.error_uri)
          done()
        }
      })

      it('should respond 401', done => {
        try {
          request.unauthorized(params)
        } catch (err) {
          expect(err.statusCode).to.equal(401)

          expect(request.res._getStatusCode()).to.equal(401)
          done()
        }
      })

      it('should respond "Unauthorized" by default', done => {
        try {
          request.unauthorized(params)
        } catch (err) {
          expect(err).to.exist()

          expect(request.res._getData()).to.equal('Unauthorized')
          done()
        }
      })

      it('should pass error to next() handler if handleErrors is false', done => {
        request.options.handleErrors = false

        try {
          request.unauthorized(params)
        } catch (err) {
          expect(err).to.exist()

          expect(request.next).to.have.been.calledWith(err)
          done()
        }
      })

      it('should set WWW-Authenticate challenge', done => {
        try {
          request.unauthorized(params)
        } catch (err) {
          expect(err).to.exist()
          let expectedHeader = 'Bearer realm="https://example.com", scope="openid", error="invalid_token", error_description="unauthorized error message", error_uri="https://example.com/errors/1"'

          expect(request.res._getHeaders()['WWW-Authenticate']).to.equal(expectedHeader)
          done()
        }
      })
    })

    describe('forbidden', () => {
      const errorMessage = 'forbidden error message'
      const params = {
        realm,
        scope: 'openid',
        error: 'error',
        error_description: errorMessage,
        error_uri: 'https://example.com/errors/1'
      }

      it('should throw a handled error', done => {
        try {
          request.forbidden(params)
        } catch (err) {
          expect(err.handled).to.be.true()
          expect(err.error).to.equal(params.error)
          expect(err.error_description).to.equal(params.error_description)
          expect(err.realm).to.equal(params.realm)
          expect(err.error_uri).to.equal(params.error_uri)
          done()
        }
      })

      it('should respond 403', done => {
        try {
          request.forbidden(params)
        } catch (err) {
          expect(err.statusCode).to.equal(403)

          expect(request.res._getStatusCode()).to.equal(403)
          done()
        }
      })

      it('should respond "Forbidden" by default', done => {
        try {
          request.forbidden(params)
        } catch (err) {
          expect(err).to.exist()

          expect(request.res._getData()).to.equal('Forbidden')
          done()
        }
      })
      it('should set WWW-Authenticate challenge', done => {
        try {
          request.forbidden(params)
        } catch (err) {
          expect(err).to.exist()
          let expectedHeader = 'Bearer realm="https://example.com", scope="openid", error="error", error_description="forbidden error message", error_uri="https://example.com/errors/1"'

          expect(request.res._getHeaders()['WWW-Authenticate']).to.equal(expectedHeader)
          done()
        }
      })
    })

    describe('internalServerError', () => {
      const error = new Error('internal')

      it('should respond 500', () => {
        request.internalServerError(error)

        expect(request.res._getStatusCode()).to.equal(500)
      })

      it('should respond "Internal Server Error" by default', () => {
        request.internalServerError(error)

        expect(request.res._getData()).to.equal('Internal Server Error')
      })

      it('should pass error to the next() handler if handleErrors is false', () => {
        request.options.handleErrors = false

        request.internalServerError(error)

        expect(request.next).to.have.been.calledWith(error)
      })
    })
  })

  describe('error', () => {
    beforeEach(() => {
      req = {}
      res = {}
      options = {}

      request = new AuthenticatedRequest(rs, req, res, next, options)
      request.internalServerError = sinon.stub()
    })

    it('ignores handled errors', () => {
      let error = new Error('message')
      error.handled = true

      request.error(error)

      expect(request.internalServerError).to.not.have.been.called()
    })

    it('passes unhandled errors to internalServerError', () => {
      let error = new Error('message')

      request.error(error)

      expect(request.internalServerError).to.have.been.calledWith(error)
    })
  })

  describe('encodeChallengeParams', () => {
    beforeEach(() => {
      req = {}
      res = {}
      options = {}

      request = new AuthenticatedRequest(rs, req, res, next, options)
    })

    it('should separate keys and values with "="', () => {
      let result = request.encodeChallengeParams({ key1: 'value1' })

      expect(result).to.equal('key1="value1"')
    })

    it('should separate parameters with ", "', () => {
      let result = request.encodeChallengeParams({ key1: 'value1', key2: 'value2' })

      expect(result).to.equal('key1="value1", key2="value2"')
    })
  })
})
