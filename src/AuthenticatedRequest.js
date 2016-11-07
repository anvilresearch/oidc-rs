/**
 * Dependencies
 */
const {JWT} = require('jose')

/**
 * AuthenticatedRequest
 */
class AuthenticatedRequest {

  /**
   * constructor
   */
  constructor (rs, req, res, next, options) {
    this.rs = rs
    this.req = req
    this.res = res
    this.next = next
    this.options = options
  }

  /**
   * authenticate
   *
   * @description
   * Authenticate an HTTP request by validating a signed JWT bearer
   * token. Handles error responses and, when authentication succeeds,
   * passes control to the middleware stack.
   *
   * @param {ResourceServer} rs
   * @param {IncomingMessage} req
   * @param {ServerResponse} res
   * @param {Function} next
   * @param {Object} options
   */
  static authenticate (rs, req, res, next, options) {
    let request = new AuthenticatedRequest(rs, req, res, next, options)

    // These methods on the request object are invoked in the promise chain
    // as callbacks. Each method in the chain takes a request instance and
    // assuming no error conditions are encountered, returns it, or returns
    // a promise that resolves it.
    Promise.resolve(request)
      .then(request.validateAuthorizationHeader)
      .then(request.validateQueryParameter)
      .then(request.validateBodyParameter)
      .then(request.requireAccessToken)
      .then(request.validateAccessToken)
      .then(request.success)

      // do nothing unless there's an explicit error argument
      // other errors are already handled
      .catch(error => {
        if (error) {
          request.internalServerError(error)
        }
      })
  }

  /**
   * validateAuthorizationHeader
   *
   * @description
   * Validate HTTP Authorization Header and extract bearer token credentials.
   * Trigger an error response in the event the header is misused.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  validateAuthorizationHeader (request) {
    let {token, req} = request
    let authorization = req.headers && req.headers.authorization

    if (authorization && token) {
      return request.badRequest('Multiple authentication methods')
    }

    if (authorization) {
      let components = authorization.split(' ')
      let [scheme, credentials] = components

      if (components.length !== 2) {
        return request.badRequest('Invalid authorization header')
      }

      if (scheme !== 'Bearer') {
        return request.badRequest('Invalid authorization scheme')
      }

      request.token = credentials
    }

    return request
  }

  /**
   * validateQueryParameter
   *
   * @description
   * Validate HTTP Query Parameter and extract bearer token credentials.
   * Trigger an error response in the event the parameter is misused. This
   * authentication is disallowed by default and must be explicitly enabled
   * by setting the `query` option to `true`.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  validateQueryParameter (request) {
    let {token, req, options} = request
    let param = req.query && req.query['access_token']

    // 💀 💀 💀 💀 💀 💀 💀         WARNING          💀 💀 💀 💀 💀 💀 💀 💀
    //
    // DO NOT ALLOW THIS AUTHENTICATION METHOD UNLESS THE USER
    // EXPLICITLY ENABLES IT. CHANCES ARE ITS USE IS NOT SECURE.
    //
    // SEE RFC 6750 SECTIONS 2.3 AND 5.3 FOR DETAILS.
    //
    //    https://tools.ietf.org/html/rfc6750#section-2.3
    //    https://tools.ietf.org/html/rfc6750#section-5.3
    //
    // 💀 💀 💀 💀 💀 💀 💀    YOU HAVE BEEN WARNED  💀 💀 💀 💀 💀 💀 💀 💀

    if (param && options.query !== true) {
      return request.badRequest('Invalid authentication method')
    }

    if (param && token) {
      return request.badRequest('Multiple authentication methods')
    }

    if (param) {
      request.token = param
    }

    return request
  }

  /**
   * validateBodyParameter
   *
   * @description
   * Validate HTTP Form Post Parameter and extract bearer token credentials.
   * Trigger an error response in the event the form parameter is misused.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  validateBodyParameter (request) {
    let {token, req} = request
    let param = req.body && req.body['access_token']
    let contentType = req.headers && req.headers['content-type']

    if (param && token) {
      return request.badRequest('Multiple authentication methods')
    }

    if (param && !contentType.includes('application/x-www-form-urlencoded')) {
      return request.badRequest('Invalid Content-Type')
    }

    if (param) {
      request.token = param
    }

    return request
  }

  /**
   * requireAccessToken
   *
   * @description
   * Ensure a bearer token is included in the request unless authentication
   * is optional.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  requireAccessToken (request) {
    let {token, options} = request
    let {realm, optional} = options

    if (!token && optional !== true) {
      return request.unauthorized({realm})
    }

    // TODO
    // should we terminate the authentication algorithm and pass control to next
    // middleware if authentication IS optional and a token is NOT present?

    return request
  }

  /**
   * validateAccessToken
   *
   * @description
   * Validate all aspects of an access token.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  validateAccessToken (request) {
    let {token, providers, options} = request
    let {realm} = options

    return Promise.resolve(request)
      .then(request.decode)
      .then(request.allow)
      .then(request.deny)
      .then(request.resolveKeys)
      .then(request.verifySignature)
      .then(request.validateExpiry)
      .then(request.validateNotBefore)
      .then(request.validateScope)
  }

  /**
   * decode
   *
   * @description
   * Decode a JWT Bearer Token and set the decoded object on the
   * AuthenticatedRequest instance.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  decode (request) {
    let {token, jwt, options: {realm}} = request

    // decode and validate the token
    try {
      jwt = JWT.decode(token)
    } catch (error) {
      return request.unauthorized({
        realm,
        error: 'invalid_token',
        error_description: 'Access token is not a JWT'
      })
    }

    let validation = jwt.validate()

    if (!validation.valid) {
      return request.badRequest('Access token is invalid')
    }

    request.jwt = jwt
    return request
  }

  /**
   * allow
   *
   * @description
   * Enforce access restrictions for issuers, audience, and subjects
   * configured using the "allow" option.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  allow (request) {
    let {jwt, options} = request
    let {allow, realm} = options
    let {iss, aud, sub} = jwt.payload

    if (allow) {
      let {issuers, audience, subjects} = allow

      if (issuers && !issuers.includes(iss)) {
        return request.forbidden({realm})
      }

      if (Array.isArray(aud) && !audience.some(id => aud.includes(id))) {
        return request.forbidden({realm})
      }

      if (typeof aud === 'string' && !audience.includes(aud)) {
        return request.forbidden({realm})
      }

      if (subjects && !subjects.includes(sub)) {
        return request.forbidden({realm})
      }
    }

    return request
  }

  /**
   * deny
   *
   * @description
   * Enforce access restrictions for issuers, audience, and subjects
   * configured using the "deny" option.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  deny (request) {
    let {jwt, options} = request
    let {deny, realm} = options
    let {iss, aud, sub} = jwt.payload

    if (deny) {
      let {issuers, audience, subjects} = deny

      if (issuers && issuers.includes(iss)) {
        return request.forbidden({realm})
      }

      if (Array.isArray(aud) && audience.some(id => aud.includes(id))) {
        return request.forbidden({realm})
      }

      if (typeof aud === 'string' && audience.includes(aud)) {
        return request.forbidden({realm})
      }

      if (subjects && subjects.includes(sub)) {
        return request.forbidden({realm})
      }
    }

    return request
  }

  /**
   * resolveKeys
   *
   * @description
   * Obtains the cryptographic key necessary to validate the JWT access token's
   * signature.
   *
   * Based on the "iss" claim in the JWT access token payload, obtain OpenID
   * Connect configuration and the JWT Set for the corresponding provider.
   * This data is cached by the ResourceServer. The cache can be persisted and
   * restored.
   *
   * In the event no suitable key can be matched based on the JWT "kid" header
   * or JWK "use" property, refresh the cached configuration and JWK Set for
   * the issuer and try again. If a key still cannot be found, authentication
   * fails.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  resolveKeys (request) {
    let providers = request.rs.providers
    let realm = request.options.realm
    let jwt = request.jwt
    let iss = jwt.payload.iss

    return providers.resolve(iss).then(provider => {
      // key matched
      if (jwt.resolveKeys(provider.jwks)) {
        return request

      // try rotating keys
      } else {
        return providers.rotate(issuer).then(provider => {
          // key matched
          if (jwt.resolveKeys(provider.jwks)) {
            return request

          // failed to match signing key
          } else {
            return request.unauthorized({
              realm,
              error: 'invalid_token',
              error_descripton: 'Cannot find key to verify JWT signature'
            })
          }
        })
      }
    })
  }

  /**
   * verifySignature
   *
   * @description
   * Verify the access token signature.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  verifySignature (request) {
    let {jwt, options: {realm}} = request

    return jwt.verify().then(verified => {
      if (!verified) {
        request.unauthorized({realm})
      }

      return request
    })
  }

  /**
   * validateExpiry
   *
   * @description
   * Ensures the access token has not expired.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  validateExpiry (request) {
    let {jwt, options: {realm}} = request
    let exp = jwt.payload.exp

    if (exp < Math.floor(Date.now() / 1000)) {
      return request.unauthorized({
        realm,
        error: 'invalid_token',
        error_description: 'Access token is expired.'
      })
    }

    return request
  }

  /**
   * validateNotBefore
   *
   * @description
   * Ensures the access token has become active.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  validateNotBefore (request) {
    let {jwt, options: {realm}} = request
    let nbf = jwt.payload.nbf

    if (nbf >= Math.ceil(Date.now() / 1000)) {
      return request.unauthorized({
        realm,
        error: 'invalid_token',
        error_description: 'Access token is not yet active.'
      })
    }

    return request
  }


  /**
   * validateScope
   *
   * @description
   * Ensures the access token has sufficient scope.
   *
   * @param {AuthenticatedRequest} request
   * @returns {AuthenticatedRequest}
   */
  validateScope (request) {
    let {jwt, options: {realm, scopes}} = request
    let scope = jwt.payload.scope

    // ensure scope is an array
    if (typeof scope === 'string') {
      scope = scope.split(' ')
    }

    // only validate scopes if configured
    if (Array.isArray(scopes)) {

      // ensure all expected scopes are present in the token
      if (!scopes.every(expected => scope.includes(expected))) {
        return request.forbidden({
          error: 'insufficient_scope',
          error_description: 'Access token has insufficient scope'
        })
      }
    }

    return request
  }

  /**
   * success
   *
   * @description
   * Pass control to the next middleware.
   *
   * @param {AuthenticatedRequest} request
   */
  success (request) {
    let {req, token, jwt, options} = request
    let {tokenProperty, claimsProperty} = options

    if (jwt) {
      req[claimsProperty || 'claims'] = jwt.payload
    }

    if (jwt && tokenProperty) {
      req[tokenProperty] = jwt
    }

    request.next()
  }

  /**
   * 400 Bad Request
   *
   * @description
   * Respond with 400 status code.
   *
   * @param {string} description
   * @returns {Promise}
   */
  badRequest (description) {
    let {res} = this

    res.status(400).json({
      error: 'invalid_request',
      error_description: description
    })

    return Promise.reject()
  }

  /**
   * 401 Unauthorized
   *
   * @description
   * Respond with 401 status code and WWW-Authenticate challenge.
   *
   * @param {Object} params
   * @returns {Promise}
   */
  unauthorized (params = {}) {
    let {res} = this

    res.set({
      'WWW-Authenticate': `Bearer ${this.encodeChallengeParams(params)}`
    })

    res.status(401).send('Unauthorized')
    return Promise.reject()
  }

  /**
   * 403 Forbidden
   *
   * @description
   * Respond with 401 status code and WWW-Authenticate challenge.
   *
   * @param {Object} params
   * @returns {Promise}
   */
  forbidden (params = {}) {
    let {res} = this

    res.set({
      'WWW-Authenticate': `Bearer ${this.encodeChallengeParams(params)}`
    })

    res.status(403).send('Forbidden')
    return Promise.reject()
  }

  /**
   * 500 Internal Server Error
   *
   * @description
   * Respond with 500 status code.
   *
   * @param {Error} error
   */
  internalServerError (error) {
    console.log(error)
    this.res.status(500).send('Internal Server Error')
  }

  /**
   * encodeChallengeParams
   *
   * @description
   * Encode parameters for WWW-Authenticate challenge header.
   *
   * @param {Object} params
   * @return {string}
   */
  encodeChallengeParams (params) {
    let pairs = []

    for (let key in params) {
      pairs.push(`${key}="${params[key]}"`)
    }

    return pairs.join(', ')
  }

}

/**
 * Export
 */
module.exports = AuthenticatedRequest
