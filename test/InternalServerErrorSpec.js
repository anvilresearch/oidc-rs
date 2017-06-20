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
const { InternalServerError } = require('../src/errors/index')

describe('InternalServerError', () => {
  let error

  beforeEach(() => {
    error = new InternalServerError()
  })

  it('should be an error', () => {
    expect(error).to.be.an.instanceof(Error)
  })

  it('should not be a handled error', () => {
    expect(error.handled).to.be.undefined()
  })

  it('should set the 500 status code', () => {
    expect(error.statusCode).to.equal(500)
  })

  it('should set the error message', () => {
    expect(error.message).to.equal('Internal Server Error')
  })
})
