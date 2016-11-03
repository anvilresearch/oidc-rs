# OpenID Connect Resource Server Authentication

OpenID Connect Resource Server Authentication for Node.js

## Planned Features

* [ ] OAuth 2.0 Bearer Token Usage (RFC 6750)
* [ ] OAuth 2.0 Token Introspection (RFC 7662)
* [ ] JWT Access Token Validation (Specification pending)
* [ ] Cookie Token Authentication (Specification pending)
* [ ] Issuer discovery (OpenID Connect Discovery)
* [ ] Dynamic key rotation (OpenID Connect Core)
* [ ] Multiple issuer support
* [ ] Scope validation
* [ ] Issuer whitelisting
* [ ] Client whitelisting

## Usage

```
const express = require('express')
const ResourceServer = require('oidc-rs')

let server = express()
let rs = new ResourceServer(options)

// define middleware
let authenticate = rs.authenticate({
  scope: ['foo', 'bar'],                // optional default scope
  issuers: ['https://forge.anvil.io'],  // optional whitelist
  clients: ['uuid1', 'uuid2']           // optional whitelist
})

// global server authentication
server.use(authenticate)

// or route specific configuration
server.get('/endpoint', authenticate, (req, res, next) => {})
```

## Running tests

### Nodejs

```bash
$ npm test
```

## MIT License

Copyright (c) 2016 Anvil Research, Inc.


