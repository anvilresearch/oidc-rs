# NOTICE

We’re archiving Anvil Connect and all related packages. This code is entirely MIT Licensed. You’re free to do with it what you want. That said, we are recommending _**against**_ using it, due to the potential for security issues arising from unmaintained software. For more information, see the announcement at [anvil.io](https://anvil.io).

# OpenID Connect Resource Server Authentication

OpenID Connect Resource Server Authentication for Node.js

## Features

* [x] OAuth 2.0 Bearer Token Usage (RFC 6750)
* [x] JWT Access Token Validation (Specification pending)
* [x] Issuer discovery (OpenID Connect Discovery)
* [x] Dynamic key rotation (OpenID Connect Core)
* [x] Multiple issuer support
* [x] Scope validation
* [x] Allow and deny access by "iss", "aud", and "sub" claims
* [ ] OAuth 2.0 Token Introspection (RFC 7662)
* [ ] Cookie Token Authentication (Specification pending)

## Usage

### Install

We're still tidying up a few things. The package will be published to npm after testing and docs are complete.

```bash
$ npm install https://github.com/anvilresearch/oidc-rs.git
```

### Require

```
const ResourceServer = require('oidc-rs')
```

### ResourceServer

ResourceServer maintains a cache of provider metadata and JSON Web Keys for verifying signatures. Provider discovery and acquisition of keys takes place when a JWT access token is decoded. The provider metadata and JWK Set are cached in memory. Therefore no configuration is required.

```
let rs = new ResourceServer()
```

The provider cache can be serialized and persisted, then restored like so:

```
let providers = require('./providers.json')
ResourceServer.from({providers}).then(rs => /* ... */)
```

#### Global server authentication

```javascript
const app = express()
app.use(rs.authenticate(options))
```

#### Route specific configuration

```javascript
app.get('/endpoint', rs.authenticate(options), (req, res, next) => {})
```

### Middleware Options

No configuration is _required_ in order to start using this middleware. All options are optional.

```javascript
rs.authenticate({
  realm: 'user',
  scopes: ['foo', 'bar'],
  allow: {
    issuers: ['https://forge.anvil.io'],
    audience: ['clientid1', 'clientid2'],
    subjects: ['userid1', 'userid2', 'useridn']
  },
  deny: { // probably want to use either allow or deny, but not both
    issuers: ['https://forge.anvil.io'],
    audience: ['clientid1', 'clientid2'],
    subjects: ['userid1', 'userid2', 'useridn']
  },
  handleErrors: false, // defaults to true
  tokenProperty: 'token',
  claimsProperty: 'claims'
})
```

* `realm` – Value of "realm" parameter to use in WWW-Authenticate challenge header.
* `scopes` – Array of scope values required to access this resource.
* `allow` – Object with arrays of allowed issuers, audience and subjects.
* `deny` – Object with arrays of restricted issuers, audience and subjects.
* `handleErrors` – When set to false, error conditions will result in a call to `next()`, passing control to the application's error handling.
* `tokenProperty` – Name of property on `req` to assign decoded JWT object. The property will not be set unless defined.
* `claimsProperty` – name of property on `req` to assign verified JWT claims. Defaults to "claims".

## Running tests

### Nodejs

```bash
$ npm test
```

## MIT License

Copyright (c) 2016 Anvil Research, Inc.


