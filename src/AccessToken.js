'use strict'

const {UnauthorizedError, ForbiddenError} = require('./errors/index')

class AccessToken {
  /**
   * @param jwt {JWT}
   *
   * @param jwt.payload {Object}
   */
  constructor (jwt) {
    this.isPoPToken = false

    this.jwt = jwt
  }

  /**
   * @returns {string|Array<string>}
   */
  get aud () {
    return this.jwt.payload.aud
  }

  /**
   * @return {Object}
   */
  get claims () {
    return this.jwt.payload
  }

  /**
   * @returns {string}
   */
  get iss () {
    return this.jwt.payload.iss
  }

  /**
   * @returns {string}
   */
  get sub () {
    return this.jwt.payload.sub
  }

  /**
   * @param jwks {JWKSet|Array<JWK>|JWK}
   *
   * @throws {DataError} If invalid jwks
   *
   * @returns {boolean}
   */
  resolveKeys (jwks) {
    return this.jwt.resolveKeys(jwks)
  }

  /**
   * @throws {UnauthorizedError} If access token is expired (or exp claim missing)
   */
  validateExpiry () {
    let exp = this.jwt.payload.exp

    if (!exp) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: 'Access token expiration claim is required'
      })
    }

    if (exp < Math.floor(Date.now() / 1000)) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: 'Access token is expired'
      })
    }
  }

  /**
   * @throws {UnauthorizedError}
   */
  validateNotBefore () {
    let nbf = this.jwt.payload.nbf

    if (nbf >= Math.ceil(Date.now() / 1000)) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: 'Access token is not yet active'
      })
    }
  }

  /**
   * @param scopes {Array<string>|undefined}
   *
   * @throws {ForbiddenError} If invalid/insufficient scope
   */
  validateScope (scopes) {
    let scope = this.jwt.payload.scope

    // ensure scope is an array
    if (typeof scope === 'string') {
      scope = scope.split(' ')
    }

    // only validate scopes if configured
    if (Array.isArray(scopes)) {
      // ensure all expected scopes are present in the token
      if (!scope || !scopes.every(expected => scope.includes(expected))) {
        throw new ForbiddenError({
          error: 'insufficient_scope',
          error_description: 'Access token has insufficient scope'
        })
      }
    }
  }

  /**
   * @returns {Promise<boolean>}
   */
  verifySignature () {
    return this.jwt.verify()
  }
}

module.exports = AccessToken
