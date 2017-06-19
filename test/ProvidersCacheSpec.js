/**
 * Test dependencies
 */
const chai = require('chai')
const sinon = require('sinon')
const nock = require('nock')

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
const {JWKSet} = require('@trust/jose')
const ProvidersCache = require('../src/ProvidersCache')

/**
 * Tests
 */
describe('ProvidersCache', () => {
  const providerConfig = require('./resources/example.com/openid-configuration.json')
  const providerJwks = require('./resources/example.com/jwks.json')

  afterEach(() => {
    nock.cleanAll()
  })

  describe('constructor', () => {
    it('should initialize an empty providers cache by default', () => {
      let cache = new ProvidersCache()

      expect(cache.providers).to.eql({})
    })
  })

  describe('static from', () => {
    it('should initialize a providers cache instance from empty data', () => {
      let data = {}

      return ProvidersCache.from(data)
        .then(cache => {
          expect(cache.providers).to.eql({})
        })
    })

    it('should import the keys of the provided provider data', () => {
      let data = {
        'https://example.com': {
          jwks: providerJwks
        }
      }

      return ProvidersCache.from(data)
        .then(cache => {
          let provider = cache.providers['https://example.com']

          expect(provider.jwks).to.be.an.instanceof(JWKSet)
        })
    })
  })

  describe('discover', () => {
    it('should fetch the openid configuration for a given issuer', () => {
      let issuer = 'https://example.com'
      nock(issuer)
        .get('/.well-known/openid-configuration')
        .reply(200, providerConfig)

      let cache = new ProvidersCache()

      return cache.discover(issuer)
        .then(res => {
          expect(res.issuer).to.equal(issuer)
          expect(res.authorization_endpoint).to.equal(issuer + '/authorize')
        })
    })
  })

  describe('jwks', () => {
    it('should fetch the public keys for a given issuer', () => {
      let issuer = 'https://example.com'
      nock(issuer)
        .get('/jwks')
        .reply(200, providerJwks)

      let cache = new ProvidersCache()

      return cache.jwks(issuer + '/jwks')
        .then(jwks => {
          expect(jwks.keys[0].kid).to.equal('2koDA6QjhXU')
        })
    })
  })

  describe('resolve', () => {
    let cache

    beforeEach(() => {
      cache = new ProvidersCache()

      sinon.spy(cache, 'rotate')
    })

    it('should fetch an issuer from cache is available', () => {
      let issuerUri = 'https://example.com'
      let issuer1 = { issuer: issuerUri }

      cache.providers[issuerUri] = issuer1

      return cache.resolve(issuerUri)
        .then(result => {
          expect(result).to.equal(issuer1)
          expect(cache.rotate).to.not.have.been.called()
        })
    })

    it('should discover and resolve an issuer when not available', () => {
      let issuerUri = 'https://example.com'
      let issuer1 = { configuration: { issuer: issuerUri } }

      cache.rotate = sinon.stub().withArgs(issuerUri).resolves(issuer1)

      return cache.resolve(issuerUri)
        .then(result => {
          expect(cache.rotate).to.have.been.called()
          expect(result.configuration.issuer).to.equal(issuerUri)
        })
    })
  })

  describe('rotate', () => {
    const issuerUri = 'https://example.com'
    let cache

    beforeEach(() => {
      cache = new ProvidersCache()

      nock(issuerUri)
        .get('/.well-known/openid-configuration')
        .reply(200, providerConfig)
      nock(issuerUri)
        .get('/jwks')
        .reply(200, providerJwks)
    })

    it('should discover and load provider config and keys', () => {
      return cache.rotate(issuerUri)
        .then(result => {
          expect(result.configuration.issuer).to.equal(issuerUri)
          expect(result.jwks).to.exist()
        })
    })

    it('should add the discovered/loaded provider to its cache', () => {
      return cache.rotate(issuerUri)
        .then(result => {
          expect(cache.providers[issuerUri]).to.equal(result)
        })
    })
  })
})
