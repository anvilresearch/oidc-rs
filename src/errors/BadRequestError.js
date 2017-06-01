/**
 * BadRequestError
 */
class BadRequestError extends Error {
  constructor (params) {
    super(params.error_description)

    this.handled = true
    this.statusCode = 400
    this.error = params.error
    this.error_description = params.error_description
    this.error_uri = params.error_uri
  }
}

/**
 * Export
 */
module.exports = BadRequestError
