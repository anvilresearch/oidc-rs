/**
 * Test dependencies
 */
const chai = require('chai')

/**
 * Assertions
 */
chai.use(require('dirty-chai'))
chai.should()
let expect = chai.expect

/**
 * Code under test
 */
const { UnauthorizedError } = require('../src/errors/index')

describe('UnauthorizedError', () => {
  let error
  let params = {
    realm: 'https://example.com',
    error: 'Error message',
    error_description: 'Longer error description',
    error_uri: 'https://example.com/errors/1'
  }

  beforeEach(() => {
    error = new UnauthorizedError(params)
  })

  it('should be an error', () => {
    expect(error).to.be.an.instanceof(Error)
  })

  it('should be a handled error', () => {
    expect(error.handled).to.be.true()
  })

  it('should set the 401 status code', () => {
    expect(error.statusCode).to.equal(401)
  })

  it('should set the realm property', () => {
    expect(error.realm).to.equal('https://example.com')
  })

  it('should set the error property', () => {
    expect(error.error).to.equal('Error message')
  })

  it('should set the error_description property', () => {
    expect(error.error_description).to.equal('Longer error description')
  })

  it('should set the error_uri property', () => {
    expect(error.error_uri).to.equal('https://example.com/errors/1')
  })
})
