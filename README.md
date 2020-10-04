# Kong Upstream JWT Extended Plugin

## Overview
This plugin is a fork of [kong-upstream-jwt](https://github.com/Optum/kong-upstream-jwt) with extended features.

This plugin will add a signed [JSON Web Token (JWT)](https://en.wikipedia.org/wiki/JSON_Web_Token) into the HTTP Header of proxied requests through the Kong gateway.
The purpose of this, is to provide means of _Authentication_, _Authorization_ and _Non-Repudiation_ to API providers
(APIs for which Kong is a gateway).

In short, API Providers require a means of cryptographically validating that requests they receive were:
A. proxied by Kong, and B. not tampered with during transmission from Kong -> API Provider.
This token accomplishes both as follows:

1. **Authentication** & **Authorization** - Provided by means of JWT signature validation. The API Provider will validate the signature on the JWT token (which is generating using Kong's RSA x509 private key), using Kong's public key. This public key can be maintained in a keystore, or sent with the token in the field `x5c` - provided API providers validate the signature chain against their truststore.

2. **Non-Repudiation** - SHA256 is used to hash the body of the HTTP request and query string of the НТТР request URL, and the resulting digests are included in the `bodyhash` and `queryhash` elements of the field (claim) `kong` of JWT payload. API Providers will take the SHA256 hashes of the HTTP request body and HTTP request query string, and compare the digests to that found in the JWT payload. If they are identical, the request remained intact during transmission. Also information about consumer, credential, route and service may be added to field (claim) `kong` of JWT payload.

## Supported Kong Releases

- Kong >= 1.0.x 

## Installation

Recommended:
```
$ luarocks install kong-upstream-jwt-extended
```

Other:
```
$ git clone https://github.com/andrey-tech/kong-upstream-jwt-extended.git /path/to/kong/plugins/kong-upstream-jwt
$ cd /path/to/kong/plugins/kong-upstream-jwt-extended
$ luarocks make *.rockspec
```

## JWT Token
The following is an example of the contents of the decoded JWT token:

**Header:**
```json
{
  "x5c": ["...der-encoded cert data..."],
  "alg": "RS256",
  "typ": "JWT",
  "kid": "..conf.key_id.." // Only present if conf.key_id configuration variable set
}
```

**Payload:**
```js
{
  "aud": "Service-1", // (Audience) Only set if aud enabled in configuration (Kong service name)
  "iss": "issuer", // (Issuer) Only set if issuer configuration variable is not blank
  "iat": 1550258274, // (Issued at) Only set if iat enabled in configuration 
  "exp": 1550258334, // 60 seconds exp time
  "jti": "d4f10edb-c4f0-47d3-b7e0-90a30a885a0b", // Unique to every request - UUID
  "kong": {
    "bodyhash": "...SHA256 hash of request body...",
    "queryhash": "...SHA256 hash of request query string...",
    "consumer": {
      "username": "Company A"
      "id": "e96dcb71-4322-490d-b6c6-b9ba1a24b6e3",
    },
    "credential": {
      "key": "q2QiVe24S6ABaO2L9dEA9y1epX25B9gr"
    },
    "route": {
      "name": "Route-1",
      "id": "cc04e82e-8b20-40f0-9081-830caa4cf13e"
    },
    "service": {
      "id": "d0395ad5-9e53-47c4-a5f2-a4c3c5250c8a",
      "name": "Service-1"
    }
  }
}
```

## Configuration

### Private and Public Keys
The plugin requires that Kong's private key be accessible in order to sign the JWT. [We also include the x509 cert in the `x5c` JWT Header for use by API providers to validate the JWT](https://tools.ietf.org/html/rfc7515#section-4.1.6).

### JWT Issuer
[JWT Issuer](https://tools.ietf.org/html/rfc7519#section-4.1.1) allows for the `iss` field to be set within the `JWT` token.

More information about JWT claims can be found [here](https://tools.ietf.org/html/rfc7519#section-4)

**Optional Plugin schema configurations:**
```
private_key_location = "/path/to/kong/ssl/privatekey.key"
public_key_location = "/path/to/kong/ssl/kongpublickey.cer"
issuer = "issuer"
key_id = "keyId"
header = "JWT" //If you want to set the header key to something other than JWT
include_credential_type = false //Controls "Bearer " + JWT or just JWT in header
```

The first contains the path to your .key file, the second specifies the path to your public key in DER format .cer file.

#### Backwards Compatibility
To maintain backwards compatibility, support for passing the key locations through environment variables is also available.  We access these via Kong's overriding environment variables `KONG_SSL_CERT_KEY` for the private key as well as `KONG_SSL_CERT_DER` for the public key.

**If not already set, these can be done so as follows:**
```
$ export KONG_SSL_CERT_KEY="/path/to/kong/ssl/privatekey.key"
$ export KONG_SSL_CERT_DER="/path/to/kong/ssl/kongpublickey.cer"
```

**One last step** is to make the environment variables accessible by an nginx worker. To do this, simply add these line to your _nginx.conf_
```
env KONG_SSL_CERT_KEY;
env KONG_SSL_CERT_DER;
```

## Maintainers
[jeremyjpj0916](https://github.com/jeremyjpj0916)  
[rsbrisci](https://github.com/rsbrisci)  

Feel free to open issues, or refer to our [Contribution Guidelines](https://github.com/Optum/kong-upstream-jwt/blob/master/CONTRIBUTING.md) if you have any questions.
