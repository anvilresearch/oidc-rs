/**
 * ForbiddenError
 */
class ForbiddenError extends Error {
  constructor (params) {
    super('Forbidden')

    this.handled = true
    this.statusCode = 403
    this.realm = params.realm
    this.error = params.error
    this.error_description = params.error_description
    this.error_uri = params.error_uri
  }
}

/**
 * Export
 */
module.exports = ForbiddenError
