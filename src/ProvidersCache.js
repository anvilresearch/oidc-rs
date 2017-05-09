/**
 * Dependencies
 */
const fetch = require('node-fetch')
const {JWKSet} = require('@trust/jose')

/**
 * ProvidersCache
 *
 * {
 *   'https://forge.anvil.io': {
 *
 *   }
 * }
 *
 *
 * let providers = new ProvidersCache(data)
 *
 * providers.resolve(issuer).then(...)
 * providers.rotate(issuer).then(...)
 */
class ProvidersCache {

  /**
   * constructor
   */
  constructor (providers = {}) {
    this.providers = providers
  }

  /**
   * from
   */
  static from (data) {
    let cache = new ProvidersCache(data)
    let providers = cache.providers
    let promises = []

    Object.keys(providers).forEach(key => {
      let provider = providers[key]

      promises.push(
        JWKSet.importKeys(provider.jwks).then(jwks => provider.jwks = jwks)
      )
    })

    return Promise.all(promises).then(() => cache)
  }

  /**
   * discover
   *
   * @description
   * Fetch the OpenID Configuration for an issuer, fetch JWK Set using
   * the configured jwks_url fo
   *
   * @param {string} issuer
   * @returns {Promise}
   */
  discover (issuer) {
    return fetch(`${issuer}/.well-known/openid-configuration`)
      //.then(validateStatus)
      .then(response => response.json())
  }

  /**
   * jwks
   *
   * @description
   * Fetch the JWK Set from a given endpoint and import to Web Crypto API.
   *
   * @param {string} endpoint
   * @returns {Promise}
   */
  jwks (endpoint) {
    return fetch(endpoint)
      //.then(validateStatus)
      .then(response => response.json())
      .then(data => JWKSet.importKeys(data))
  }

  /**
   * resolve
   *
   * @description
   * Provide a cached provider object or discover the provider.
   *
   * @param {string} issuer
   * @returns {Promise}
   */
  resolve (issuer) {
    let provider = this.providers[issuer]

    if (provider) {
      return Promise.resolve(provider)
    } else {
      return this.rotate(issuer)
    }
  }

  /**
   * rotate
   *
   * @param {string} issuer
   * @returns {Promise}
   */
  rotate (issuer) {
    let providers = this.providers
    let provider = {}

    return this.discover(issuer)
      .then(configuration => provider.configuration = configuration)
      .then(configuration => this.jwks(configuration.jwks_uri))
      .then(jwks => provider.jwks = jwks)
      .then(() => {
        providers[issuer] = provider
        return provider
      })
  }

}

/**
 * Export
 */
module.exports = ProvidersCache
