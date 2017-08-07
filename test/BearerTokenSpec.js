'use strict'

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
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const BearerToken = require('../src/BearerToken')

/**
 * Tests
 */
describe('BearerToken', () => {
  describe('from', () => {
    it('should create a bearer token instance', () => {
      let jwt = { header: {}, payload: {} }
      let token = BearerToken.from(jwt)

      expect(token.accessToken).to.equal(jwt)
    })
  })

  describe('claim getters getters', () => {
    const jwt = {
      payload: {
        iss: 'https://provider.com',
        aud: 'https://rp.com',
        sub: 'user123'
      }
    }
    const token = BearerToken.from(jwt)

    it('should return the jwt payload iss', () => {
      let { iss } = token

      expect(iss).to.equal(jwt.payload.iss)
    })

    it('should return the jwt payload sub', () => {
      let { sub } = token

      expect(sub).to.equal(jwt.payload.sub)
    })

    it('should return the jwt payload aud', () => {
      let { aud } = token

      expect(aud).to.equal(jwt.payload.aud)
    })
  })
})
