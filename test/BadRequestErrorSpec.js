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
const { BadRequestError } = require('../src/errors/index')

describe('BadRequestError', () => {
  let error
  let params = {
    error: 'Error message',
    error_description: 'Longer error description',
    error_uri: 'https://example.com/errors/1'
  }

  beforeEach(() => {
    error = new BadRequestError(params)
  })

  it('should be an error', () => {
    expect(error).to.be.an.instanceof(Error)
  })

  it('should be a handled error', () => {
    expect(error.handled).to.be.true()
  })

  it('should set the 400 status code', () => {
    expect(error.statusCode).to.equal(400)
  })

  it('should set the error message', () => {
    expect(error.message).to.equal('Longer error description')
  })

  it('should set the error_description property', () => {
    expect(error.error_description).to.equal('Longer error description')
  })

  it('should set the error_uri property', () => {
    expect(error.error_uri).to.equal('https://example.com/errors/1')
  })
})
