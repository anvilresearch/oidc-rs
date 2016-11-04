/**
 * Dependencies
 */
const {JWT} = require('jose')

/**
 * AuthenticatedRequest
 */
class AuthenticatedRequest {

  constructor (rs, req, res, next, options) {
    this.rs = rs
    this.req = req
    this.res = res
    this.next = next
    this.options = options
  }


  static authenticate (rs, req, res, next, options) {
    let request = new AuthenticatedRequest(rs, req, res, next, options)

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
   */
  validateQueryParameter (request) {
    let {token, req, options} = request
    let param = req.query && req.query['access_token']

    // 💀 💀 💀 💀 💀 💀 💀         WARNING          💀 💀 💀 💀 💀 💀 💀 💀
    //
    // DO NOT ALLOW THIS AUTHENTICATION METHOD UNLESS THE USER
    // EXPLICITLY ENABLES IT. CHANCES ARE IT'S USE IS NOT SECURE.
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
   */
  validateBodyParameter (request) {
    let {token, req} = request
    let param = req.body && req.body['access_token']
    let contentType = req.headers && req.headers['content-type']

    if (param && token) {
      return request.badRequest('Multiple authentication methods')
    }

    if (param && contentType !== 'application/x-www-form-urlencoded') {
      return request.badRequest('Invalid Content-Type')
    }

    if (param) {
      request.token = param
    }

    return request
  }

  /**
   * requireAccessToken
   */
  requireAccessToken (request) {
    let {token, options} = request
    let {realm, optional} = options

    if (!token && optional !== true) {
      return request.unauthorized({realm})
    }

    return request
  }

  /**
   * validateAccessToken
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
      .catch(internalServerError)
  }

  /**
   * decode
   */
  decode (request) {
    let {token} = request

    // decode and validate the token
    let jwt = JWT.decode(token)
    let validation = jwt.validate()

    if (!validation.valid) {
      request.badRequest('Can\'t decode bearer token as a JWT')
    }

    request.jwt = jwt
    return request
  }

  /**
   * allow
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
   */
  resolveKeys (request) {
    let {rs: {providers}, options: {realm}} = request

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
   */
  success (request) {
    request.next()
  }

  /**
   * 400 Bad Request
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
   */
  unauthorized (params = {}) {
    let {res} = this

    res.set({
      'WWW-Authenticate', `Bearer ${this.encodeChallengeParams(params)}`
    })

    res.status(401).send('Unauthorized')
    return Promise.reject()
  }

  /**
   * 403 Forbidden
   */
  forbidden (params = {}) {
    let {res} = this

    res.set({
      'WWW-Authenticate', `Bearer ${this.encodeChallengeParams(params)}`
    })

    res.status(403).send('Forbidden')
    return Promise.reject()
  }

  /**
   * 500 Internal Server Error
   */
  internalServerError (error) {
    this.res.status(500).send('Internal Server Error')
  }

  /**
   * encodeChallengeParams
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
