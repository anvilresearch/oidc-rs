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
const ProvidersCache = require('../src/ProvidersCache')
const ResourceServer = require('../src/ResourceServer')
const AuthenticatedRequest = require('../src/AuthenticatedRequest')

/**
 * Tests
 */
describe('ResourceServer', () => {
  describe('constructor', () => {
    it('should initialize an empty ResourceServer instance', () => {
      let rs = new ResourceServer()

      expect(rs.providers).to.exist()
      expect(rs.providers).to.be.an.instanceof(ProvidersCache)
    })

    it('should throw an error on an invalid providers cache option', () => {
      let options = { providers: {} }

      expect(() => new ResourceServer(options))
        .to.throw(/providers option must be an instance of ProvidersCache/)
    })

    it('should init an RS instance from serialized JSON string', () => {
      let serializedRs = JSON.stringify({ defaults: { scope: ['defaultScope'] } })

      return ResourceServer.from(serializedRs)
        .then(rs => {
          expect(rs.defaults.scope).to.eql(['defaultScope'])
        })
    })
  })

  describe('static from', () => {
    it('should return a ResourceServer instance', () => {
      return ResourceServer.from({})
        .then(rs => {
          expect(rs).to.be.an.instanceof(ResourceServer)
          expect(rs.providers).to.exist()
          expect(rs.providers).to.be.an.instanceof(ProvidersCache)
        })
    })
  })

  describe('authenticate', () => {
    it('should invoke AuthenticatedRequest.authenticate', () => {
      AuthenticatedRequest.authenticate = sinon.stub()

      let rsOptions = {
        defaults: {
          scope: ['defaultScope']
        }
      }

      let rs = new ResourceServer(rsOptions)

      let handlerOptions = {
        allow: {
          issuers: 'https://example.com'
        }
      }

      let authHandler = rs.authenticate()

      let req = {}
      let res = {}
      let next = () => {}

      authHandler(req, res, next)

      expect(AuthenticatedRequest.authenticate)
        .to.have.been.calledWith(rs, req, res, next)
    })
  })
})
