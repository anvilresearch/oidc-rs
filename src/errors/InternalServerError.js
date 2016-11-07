/**
 * InternalServerError
 */
class InternalServerError extends Error {
  constructor () {
    super('Internal Server Error')
    this.statusCode = 500
  }
}

/**
 * Export
 */
module.exports = InternalServerError
