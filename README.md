# Kong Upstream JWT Extended Plugin

## Overview
This plugin is a fork of [kong-upstream-jwt](https://github.com/Optum/kong-upstream-jwt) with **extended features**.

This plugin will add a signed [JSON Web Token (JWT)](https://en.wikipedia.org/wiki/JSON_Web_Token) into the HTTP Header of proxied requests through the Kong gateway.
The purpose of this, is to provide means of _Authentication_, _Authorization_ and _Non-Repudiation_ to API providers
(APIs for which Kong is a gateway).

In short, API Providers require a means of cryptographically validating that requests they receive were:
A. proxied by Kong, and B. not tampered with during transmission from Kong -> API Provider.
This token accomplishes both as follows:

1. **Authentication** & **Authorization** - Provided by means of JWT signature validation.
The API Provider will validate the signature on the JWT token (which is generating using Kong's RSA x509 private key),
using Kong's public key. This public key can be maintained in a keystore, or sent with the token in the field `x5c` -
provided API providers validate the signature chain against their truststore.

2. **Non-Repudiation** - SHA256 is used to hash the body of the HTTP request and query string of the НТТР request URL,
and the resulting digests are included in the `bodyhash` and `queryhash` elements of the field (claim) `kong` of JWT payload.
API Providers will take the SHA256 hashes of the HTTP request body and HTTP request query string,
and compare the digests to that found in the JWT payload.
If they are identical, the request remained intact during transmission.
Also information about consumer, credential, route and service may be added to field (claim) `kong` of JWT payload.

## Supported Kong Releases

- Kong >= 1.0.x

## Installation

Recommended:
```
$ luarocks install kong-upstream-jwt-extended
```

Other:
```
$ git clone https://github.com/andrey-tech/kong-upstream-jwt-extended.git /path/to/kong/plugins/kong-upstream-jwt-extended
$ cd /path/to/kong/plugins/kong-upstream-jwt-extended
$ luarocks make *.rockspec
```

## JWT Token

### Header

Field  |  Config parameter | Description
-------| ------------------ | ------------
[typ](https://tools.ietf.org/html/rfc7515#section-4.1.9)   |           | Token type (JWT)
[alg](https://tools.ietf.org/html/rfc7515#section-4.1.1)   |           | Message authentication code algorithm (RS256)
[x5c](https://tools.ietf.org/html/rfc7515#section-4.1.6)   | x5c       | A X.509 certificate chain in [RFC4945](https://tools.ietf.org/html/rfc4945) format corresponding to the private key used to generate the token signature for use by API providers to validate the JWT
[kid](https://tools.ietf.org/html/rfc7515#section-4.1.4)   | key id    | A hint indicating which key the client used to generate the token signature

The following is an example of the contents of the decoded JWT header:
```json
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "key-id-001",
  "x5c": ["...der-encoded cert data..."]
}
```

### Payload

Field  |  Config parameter | Description
-------| ------------------ | ------------
[aud](https://tools.ietf.org/html/rfc7519#section-4.1.3)   | aud      | Identifies the recipients that the JWT is intended for (Kong service name)
[iss](https://tools.ietf.org/html/rfc7519#section-4.1.1)   | issuer   | Identifies principal that issued the JWT
[iat](https://tools.ietf.org/html/rfc7519#section-4.1.6)   | iat      | Identifies the time at which the JWT was issued
[jti](https://tools.ietf.org/html/rfc7519#section-4.1.7)   | jwt      | Case sensitive unique identifier of the token even among different issuers (unique to every request - [UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier))
[exp](https://tools.ietf.org/html/rfc7519#section-4.1.4)   | exp      | Identifies the expiration time on and after which the JWT must not be accepted for processing
kong                                                       | consumer,<br> credential,<br> route,<br> service,<br> body hash,<br> query hash | Information about consumer, credential, route, service and request from Kong

The following is an example of the contents of the decoded JWT payload:
```json
{
  "aud": "Service-1",
  "iss": "issuer",
  "iat": 1550258274,
  "exp": 1550258334,
  "jti": "d4f10edb-c4f0-47d3-b7e0-90a30a885a0b",
  "kong": {
    "request": {
      "bodyhash": "...SHA256 hash of request body...",
      "queryhash": "...SHA256 hash of request query string..."
    },
    "consumer": {
      "username": "Company A",
      "id": "e96dcb71-4322-490d-b6c6-b9ba1a24b6e3"
    },
    "credential": {
      "key": "q2QiVe24S6ABaO2L9dEA9y1epX25B9gr"
    },
    "route": {
      "name": "Route-1",
      "id": "cc04e82e-8b20-40f0-9081-830caa4cf13e"
    },
    "service": {
      "name": "Service-1",
      "id": "d0395ad5-9e53-47c4-a5f2-a4c3c5250c8a"
    }
  }
}
```

## Configuration

Configuration parameter | Type    | Description
----------------------- | ------- | -----------
issuer                  | string  | Identifies principal that issued the JWT (present in JWT payload if not blank)
private key location<sup>*</sup>    | string  | The path to your Kong's private key file (.key) to sign the JWT
public key location<sup>*</sup>     | string  | The path to your Kong's public key file (.crt)
key id                  | string  | A hint indicating which key the client used to generate the token signature. Present in JWT header if not blank
header                  | string  | Key of НТТР header (Authorization)
include bearer          | boolean | Controls "Bearer " + JWT or just JWT in header
exp                     | integer | Controls expiration time of token (beetween 0 and 86400). If 0, then exp field is not present in JWT payload
consumer                | array   | List of keys of **currently authenticated** consumer entity (use * to include all available keys)
credential              | array   | List of keys of credentials of the **currently authenticated** consumer entity (use * to include all available keys)
route                   | array   | List of keys of **current** route entity (use * to include all available keys)
service                 | array   | List of keys of **current** service entity (use * to include all available keys)
x5c                     | boolean | Controls x5c field in JWT header
aud                     | boolean | Controls aud field in JWT payload
iat                     | boolean | Controls iat field in JWT payload
jti                     | boolean | Controls jti field in JWT payload
body hash               | boolean | Controls bodyhash field in JWT payload
query hash              | boolean | Controls queryhash field in JWT payload

**\*** The plugin **requires** that Kong’s private key be accessible in order to sign the JWT.
Also X.509 cert may be included in the [x5c](https://tools.ietf.org/html/rfc7515#section-4.1.6) JWT header for use by API providers to validate the JWT.

To maintain backwards compatibility, support for passing the key locations through environment variables is also available.  We access these via Kong's overriding environment variables `KONG_SSL_CERT_KEY` for the private key as well as `KONG_SSL_CERT_DER` for the public key.

If not already set, these can be done so as follows:
```
$ export KONG_SSL_CERT_KEY="/path/to/kong/ssl/private.key"
$ export KONG_SSL_CERT_DER="/path/to/kong/ssl/public.crt"
```

One last step is to make the environment variables accessible by an nginx worker. To do this, simply add these line to your _nginx.conf_
```
env KONG_SSL_CERT_KEY;
env KONG_SSL_CERT_DER;
```

## Authors and maintainers

The original authors and maintainers of [kong-upstream-jwt](https://github.com/Optum/kong-upstream-jwt) plugin:

- [jeremyjpj0916](https://github.com/jeremyjpj0916)
- [rsbrisci](https://github.com/rsbrisci)

The author and maintainer of [kong-upstream-jwt-extended](https://github.com/andrey-tech/kong-upstream-jwt-extended) plugin:

- [andrey-tech](https://github.com/andrey-tech)

## License

This plugin is licensed under the [Apache License Version 2.0](./LICENSE).
