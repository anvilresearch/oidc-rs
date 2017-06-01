/**
 * UnauthorizedError
 */
class UnauthorizedError extends Error {
  constructor (params) {
    super('Unauthorized')

    this.handled = true
    this.statusCode = 401
    this.realm = params.realm
    this.error = params.error
    this.error_description = params.error_description
    this.error_uri = params.error_uri
  }
}

/**
 * Export
 */
module.exports = UnauthorizedError
