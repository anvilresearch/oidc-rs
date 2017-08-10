'use strict'

const AccessToken = require('./AccessToken')
const PoPToken = require('./PoPToken')

class Credential {
  /**
   * @param jwt {JWT}
   *
   * @throws {DataError} If decoding an invalid access token (inside PoPToken)
   */
  static from (jwt) {
    if (jwt.payload && jwt.payload.token_type === 'pop') {
      return new PoPToken(jwt)
    } else {
      return new AccessToken(jwt)
    }
  }
}

module.exports = Credential
