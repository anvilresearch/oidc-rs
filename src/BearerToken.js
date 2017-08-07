'use strict'

const {JWT} = require('@trust/jose')
const {UnauthorizedError, ForbiddenError} = require('./errors/index')

class BearerToken {
  constructor (jwt) {
    this.accessToken = jwt
    this.popToken = null

    let payload = jwt.payload || {}

    if (payload.token_type === 'pop') {
      this.accessToken = JWT.decode(payload.access_token || payload.id_token)
      this.popToken = jwt
    }
  }

  static from (jwt) {
    return new BearerToken(jwt)
  }

  get claims () {
    return this.accessToken.payload
  }

  get aud () {
    return this.accessToken.payload.aud
  }

  get iss () {
    return this.accessToken.payload.iss
  }

  get sub () {
    return this.accessToken.payload.sub
  }

  resolveKeys (jwks) {
    return this.accessToken.resolveKeys(jwks)
  }

  validateExpiry () {
    let exp = this.accessToken.payload.exp

    if (exp < Math.floor(Date.now() / 1000)) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: 'Access token is expired'
      })
    }

    return true
  }

  validateNotBefore () {
    let nbf = this.accessToken.payload.nbf

    if (nbf >= Math.ceil(Date.now() / 1000)) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: 'Access token is not yet active'
      })
    }
  }

  /**
   * validatePoPToken
   *
   * @description
   * If bearer token is a Proof of Possession (PoP) token, do the following:
   *
   *   1. Extract the wrapped/embedded bearer access_token or id_token
   *   2. Validate pop token signature against the `cnf` claim in bearer token
   *   3. Ensure pop token issuer equals bearer token client_id
   *   4. Ensure
   *
   * @see https://tools.ietf.org/html/rfc7800 (PoP Semantics for JWTs)
   * @see https://tools.ietf.org/html/draft-ietf-oauth-pop-key-distribution-03
   *
   * @param {AuthenticatedRequest} request
   *
   * @returns {AuthenticatedRequest}
   */
  validatePoPToken (request) {
  }

  validateScope (scopes) {
    let scope = this.accessToken.payload.scope

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

  verifySignature () {
    return this.accessToken.verify()
  }
}

module.exports = BearerToken
