## Coyote: an ACME toolkit

Coyote lets you make ACME servers, which are not guaranteed to not explode in
your face. You have to code that out yourself.

coyote aims to solve a few problems (not all of these are solved yet; see "Task List" below):

- Provide an alternative to boulder and pebble
- Provide ACME with backing storage you prefer to use, by way of Rust's traits for storage implementation.
- Provide ACME in non-conforming scenarios (e.g., behind corporate firewalls)
- Provide ACME services with hooks into the validation system, so you can implement validations however you feel like.
- It's a library; make it as big or as small as you like. No need for multiple implementations.
- A FOSS alternative to the letsencrypt canonical implementation that is _also_ tested against LE's test suite.

`acmed` comes with coyote; it is a complete example canonical implementation against PostgreSQL for backing storage and OpenSSL for crypto. It (deliberately) allows all challenges through and is not meant for production usage.

coyote is intended to let you build an `acmed` without using `acmed` itself, but that will not come until the project is complete. Until then it is a single implementation with enough traits / generic parameters to make alternatives possible later. For example, work to implement a redis-based nonce validation system would just be a trait implementation at the time of this writing, even though it is not available today.

## Running `acmed`

[acmed](examples/acmed.rs) is a very small, example implementation of coyote, intended to demonstrate usage of it. It is not meant or designed to be used in a production environment. It does not perform challenges properly, allowing all of them that come in.

You'll need `docker` to launch the postgres instance. Provide `HOSTNAME` to set a host name for TLS service; otherwise `localhost` is assumed. A CA at `ca.pem` and `ca.key` will be generated at the directory you run the `cargo` commands from, which you will need to pass to clients to your certificates. Also, a TLS in-memory cert will be generated to serve the `acmed` instance.

To launch:

```
$ make postgres
$ HOSTNAME=tls-hostname.local cargo run --bin acmed
```

It will start a service on `https://${HOSTNAME}:8000` which you can then pass as
the `--server` flag to `certbot`, e.g.:

```
certbot --server 'https://${HOSTNAME}:8000' certonly --standalone -d 'foo.com' -m 'erik+github@hollensbe.org' --agree-tos
```

Otherwise, the use is the same.

To access the postgres instance that `acmed` is running against (provided by `make postgres`):

```
psql -U postgres -h localhost coyote
```

## Tests

`docker` is required to run the tests. The tests take around 70 seconds to run on a 5900X and use all 24 threads most of the test runtime. Be mindful of the time they take, especially when running them on a slower system.

```
cargo test
```

## Task List

### JOSE/ACME Protocols:

- [x] JWS decoding; serde codec (handled in middleware)
- [x] JWK conversion to openssl types; signing and validation
- [x] Full validation and production of nonce
- [x] Full validation of ACME protected header (in middleware)
- [x] RFC7807 "problem details" HTTP error return values
- [x] Various validating codecs for ACME structs
- [ ] MAYBE: rate limiting (see 6.6 of RFC8555), but probably later
- [ ] Integration of well-used third party ACME client in testing

### Handlers:

- [x] Nonce Handlers
- [x] Nonce Middleware
- [x] Accounts (RFC8555 7.3)
  - [x] Handlers:
    - [x] New Account
    - [x] Lookup Account
    - [x] De-registration
- [x] Orders (RFC8555 7.4)
  - [x] Challenge Traits
    - [ ] HTTP basic impl: needed for certbot tests
    - [ ] MAYBE: DNS basic impl; see "Other concerns" below
  - [ ] Handlers:
    - [x] Authorization Request
    - [x] Fetch challenges
    - [x] Initiate Challenge
    - [x] Deactivate Challenge
    - [x] Challenge status
    - [x] Finalization
    - [x] Fetch Certificate
    - [ ] Revocation of Certificate
- Other concerns:
  - [ ] Key Changes (`/key-change` endpoint, see RFC8555 7.3.5)

### Storage:

- DB Layer
  - [x] PostgreSQL implementation
  - [x] Nonce storage
  - [x] Account storage
  - [x] Order information / state machine storage
  - [x] Cert storage
    - [ ] Encrypted at rest

## Things coyote doesn't currently handle

These are things that are not covered by our initial goals, and we do not feel they are higher priority items. We will happily accept pull requests for this functionality.

- Accounts:
  - Terms of Service changes
  - External Account Bindings

### LICENSE

This software is covered by the BSD-3-Clause License. See [LICENSE.txt](LICENSE.txt) for more details.
