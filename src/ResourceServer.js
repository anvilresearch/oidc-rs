/**
 * Dependencies
 */
const ProvidersCache = require('./ProvidersCache')
const AuthenticatedRequest = require('./AuthenticatedRequest')

/**
 * ResourceServer
 */
class ResourceServer {

  /**
   * constructor
   *
   * @description
   * Creates a new ResourceServer instance. The options argument can be used to
   * restore cached provider metadata and cryptographic keys obtained previously
   * through OpenID Connect Discovery.
   *
   * @param [options={}] {Object}
   * @param [options.providers] {Object}
   * @param [options.defaults] {Object}
   *
   * @example
   * ```
   * new ResourceServer({
   *   providers: {
   *     'https://forge.anvil.io': {
   *       discovery: { ... },
   *       jwks: { ... }
   *     }
   *   },
   *   defaults: {
   *     allow: {
   *       issuers: ['https://forge.anvil.io']
   *     }
   *   }
   * })
   * ```
   */
  constructor (options = {}) {
    Object.assign(this, options)

    if (!this.providers) {
      this.providers = new ProvidersCache()
    }

    if (!(this.providers instanceof ProvidersCache)) {
      throw new Error('providers option must be an instance of ProvidersCache')
    }
  }

  /**
   * from
   */
  static from (data) {
    return new Promise((resolve, reject) => {
      if (typeof data === 'string') {
        data = JSON.parse(data)
      }

      if (data.providers && !(data.providers instanceof ProvidersCache())) {
        return ProvidersCache.from(data.providers).then(cache => {
          data.providers = cache
          return new ResourceServer(data)
        })
      }

      resolve(new ResourceServer(data))
    })
  }

  /**
   * authenticate
   *
   * @description
   *
   * @param {Object} options
   * @param {Object} options.allow
   * @param {Array}  options.allow.issuers
   * @param {Array}  options.allow.audience
   * @param {Array}  options.allow.subjects
   * @param {Object} options.deny
   * @param {Array}  options.deny.issuers
   * @param {Array}  options.deny.audience
   * @param {Array}  options.deny.subjects
   * @param {Array<string>} options.scope
   *
   * @returns {Function}
   *
   * @example
   *
   * let server = express()
   * let providers = require('./providers.json')
   * let rs = new ResourceServer({providers})
   *
   * let options = {
   *   allow: {
   *     issuers: [...],
   *     audience: [...],
   *     subjects: [...]
   *   },
   *   deny: {
   *     issuers: [...],
   *     audience: [...],
   *     subjects: [...]
   *   },
   *   scope: ['my-resty-thing']
   * }
   *
   * server.use(rs.authenticate(options))
   * server.get('/endpoint', rs.authenticate(options), (req, res, next) => {})
   */
  authenticate (options = {}) {
    let {defaults} = this
    options = Object.assign({}, defaults, options)

    return (req, res, next) => {
      AuthenticatedRequest.authenticate(this, req, res, next, options)
    }
  }

}

/**
 * Export
 */
module.exports = ResourceServer
