'use strict'

const {JWT, JWK} = require('@trust/jose')
const AccessToken = require('./AccessToken')
const {UnauthorizedError} = require('./errors/index')

/**
 * Proof of Possession (PoP) token
 *
 * @see https://tools.ietf.org/html/rfc7800 (PoP Semantics for JWTs)
 * @see https://tools.ietf.org/html/draft-ietf-oauth-pop-key-distribution-03
 */
class PoPToken {
  /**
   * @param jwt {JWT}
   * @param jwt.payload {Object}
   *
   * @param jwt.payload.aud {string|Array<string>}
   *
   * One of:
   * @param [jwt.payload.access_token] {string} Compact JWT encoded
   * @param [jwt.payload.id_token] {string} Compact JWT encoded
   *
   * @throws {DataError} If decoding an invalid access token
   */
  constructor (jwt) {
    this.isPoPToken = true

    this.popToken = jwt

    this.accessToken = new AccessToken(
      JWT.decode(jwt.payload.access_token || jwt.payload.id_token)
    )
  }

  /**
   * OpenID Connect / JWT Audience claim, intended to restrict the audience of
   * the PoP token to (preferably) a single Resource Server.
   * Gets checked against `allow` and `deny` lists in `AuthenticationRequest`.
   *
   * @returns {string|Array<string>}
   */
  get aud () {
    return this.popToken.payload.aud
  }

  /**
   * @return {Object}
   */
  get claims () {
    return this.accessToken.jwt.payload
  }

  /**
   * @returns {string}
   */
  get iss () {
    return this.accessToken.jwt.payload.iss
  }

  /**
   * @returns {string}
   */
  get sub () {
    return this.accessToken.jwt.payload.sub
  }

  /**
   * @param jwks {JWKSet|Array<JWK>|JWK}
   *
   * @throws {DataError} If invalid jwks
   *
   * @returns {boolean}
   */
  resolveKeys (jwks) {
    return this.accessToken.resolveKeys(jwks)
  }

  /**
   * @throws {UnauthorizedError} If either access token or pop token is expired
   *    (or exp claim missing)
   */
  validateExpiry () {
    // Check access token expiration (throws an error if missing or expired)
    this.accessToken.validateExpiry()

    // Now check wrapper pop token expiration
    let exp = this.popToken.payload.exp

    if (!exp) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: 'PoP token expiration claim is required'
      })
    }

    if (exp < Math.floor(Date.now() / 1000)) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: 'PoP token is expired'
      })
    }
  }

  /**
   * @throws {UnauthorizedError} If access token `bnf` claim is invalid
   */
  validateNotBefore () {
    // PoP token does not have its own bnf claim, delegate to access token
    this.accessToken.validateNotBefore()
  }

  /**
   * validatePoPToken
   *
   * @description
   * Validates the outer PoP token, by ensuring the following:
   *
   *   1. Verifies the PoP token signature against the public key embedded
   *     in the access token's `cnf` key confirmation claim
   *   2. Validates that the PoP token `iss`uer (the client_id of
   *     the Presenter client) is present in the access token's `aud`ience claim
   *
   * @throws {UnauthorizedError} Rejects if signature or issuer is invalid
   *
   * @returns {Promise}
   */
  validatePoPToken () {
    return this.verifyPoPSignature()

      .then(() => this.validatePoPIssuer())
  }

  /**
   * @throws {UnauthorizedError} Rejects if signature is invalid or missing
   *
   * @returns {Promise}
   */
  verifyPoPSignature () {
    let isSigned = this.popToken.signature || this.popToken.signatures

    if (!isSigned) {
      return Promise.reject(new UnauthorizedError({
        error: 'invalid_token',
        error_description: 'PoP token signature is required'
      }))
    }

    return this.importConfirmationKey()
      .then(() => {
        return this.popToken.verify()
          .catch(() => {
            // Error during verify(), return false to be caught below
            return false
          })
      })

      .then(verified => {
        if (!verified) {
          throw new UnauthorizedError({
            error: 'invalid_token',
            error_description: 'Invalid PoP token signature'
          })
        }

        return true
      })
  }

  /**
   * @returns {Promise}
   */
  importConfirmationKey () {
    let cnfJwk = this.accessToken.jwt.payload.cnf.jwk

    if (!cnfJwk) {
      return Promise.reject(new UnauthorizedError({
        error: 'invalid_token',
        error_description: 'Missing cnf key in access token'
      }))
    }

    return JWK.importKey(cnfJwk)

      .then(importedJwk => {
        this.popToken.key = importedJwk.cryptoKey
      })

      .catch(() => {
        throw new UnauthorizedError({
          error: 'invalid_token',
          error_description: 'Invalid cnf key in access token'
        })
      })
  }

  /**
   * @throws {UnauthorizedError} If pop token issuer is invalid
   */
  validatePoPIssuer () {
    const popIssuer = this.popToken.payload.iss

    if (!popIssuer) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: 'PoP token issuer claim required'
      })
    }

    let audience = this.accessToken.jwt.payload.aud

    // Audience is either an array or a string (for single audiences)
    if (typeof audience === 'string') {
      audience = [ audience ]
    }

    const issuerAuthorized = audience.some(aud => popIssuer === aud)
    if (!issuerAuthorized) {
      throw new UnauthorizedError({
        error: 'invalid_token',
        error_description: 'PoP token issuer not authorized in access token audience'
      })
    }
  }

  /**
   * @param scopes {Array<string>|undefined}
   *
   * @throws {ForbiddenError} If invalid/insufficient scope
   */
  validateScope (scopes) {
    // PoP token does not have its own scope, delegate to access token
    this.accessToken.validateScope(scopes)
  }

  /**
   * @returns {Promise<boolean>}
   */
  verifySignature () {
    // First, verify embedded access token signature
    return this.accessToken.verifySignature()
      .then(verified => {
        if (!verified) { return false }

        // Access token verified, now verify outer pop token signature
        // against the key from the `cnf` claim in access token
        return this.verifyPoPSignature()
      })
  }
}

module.exports = PoPToken
