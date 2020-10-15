# Kong Upstream JWT Extended Plugin

![Kong logo](./assets/kong-logo.png)

## Overview

[Russian version (русскоязычная версия)](#russian-version)

This plugin is a fork of [kong-upstream-jwt](https://github.com/Optum/kong-upstream-jwt) and **extends its features**.

This plugin will add a signed (RS256 algorithm) [JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token) (JWT)
into the HTTP Header `Authorization` of proxied requests through the Kong gateway.
The purpose of this, is to provide means of _Authentication_, _Authorization_ and _Non-Repudiation_ to API providers
(APIs for which Kong is a gateway).

In short, API Providers require a means of cryptographically validating that requests they receive were:
A. proxied by Kong, and B. not tampered with during transmission from Kong to API Provider.
This token accomplishes both as follows:

1. **Authentication** & **Authorization** - Provided by means of JWT signature validation.
The API Provider will validate the signature on the JWT token (which is generated using Kong's RSA private key),
using Kong's [X.509 public key certificate](https://en.wikipedia.org/wiki/X.509).
This X.509 public key certificate can be maintained in a keystore,
or sent with the token in the field [`x5c`](https://tools.ietf.org/html/rfc7515#section-4.1.6)
- provided API providers validate the signature chain against their truststore.

2. **Non-Repudiation** - SHA256 is used to hash the body of the HTTP request and query string of the НТТР request URL.
The resulting digests are included in the `bodyhash` and `queryhash` elements of the field `kong` of JWT payload.
API Providers will take the SHA256 hashes of the HTTP request body and HTTP request URL query string
to compare the digests to that found in the JWT payload.
If they are identical, the request remaines intact during transmission.
Also, information about consumer, credentials, route and service can be added to field `kong` of JWT payload.

## Supported Kong Releases

- Kong >= 1.0.x

## Installation

This plugin is available on [LuaRocks](https://luarocks.org/modules/andrey-tech/kong-upstream-jwt-extended).

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

Field  | Configuration           | Description
-------| ----------------------- | ------------
[`typ`](https://tools.ietf.org/html/rfc7515#section-4.1.9)   |           | Token type (JWT)
[`alg`](https://tools.ietf.org/html/rfc7515#section-4.1.1)   |           | Message authentication code algorithm (RS256)
[`x5c`](https://tools.ietf.org/html/rfc7515#section-4.1.6)   | x5c       | A X.509 certificate chain in [RFC4945](https://tools.ietf.org/html/rfc4945) format corresponding to the private key used to generate the token signature for use by API providers to validate the JWT
[`kid`](https://tools.ietf.org/html/rfc7515#section-4.1.4)   | key id    | A hint indicating which key the client used to generate the token signature

The following is an example of the contents of the decoded JWT header:
```json
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "key-id-001",
  "x5c": ["...X.509 public key certificate data..."]
}
```

### Payload

Field  | Configuration | Description
-------| ------------- | ------------
[`aud`](https://tools.ietf.org/html/rfc7519#section-4.1.3)   | aud      | Identifies the recipients that the JWT is intended for (Kong service name)
[`iss`](https://tools.ietf.org/html/rfc7519#section-4.1.1)   | issuer   | Identifies principal that issued the JWT
[`iat`](https://tools.ietf.org/html/rfc7519#section-4.1.6)   | iat      | Identifies the time at which the JWT was issued
[`jti`](https://tools.ietf.org/html/rfc7519#section-4.1.7)   | jwt      | Case sensitive unique identifier of the token even among different issuers (unique to every request - [UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier))
[`exp`](https://tools.ietf.org/html/rfc7519#section-4.1.4)   | exp      | Identifies the expiration time on and after which the JWT must not be accepted for processing
`kong`                                                       | consumer,<br> credentials,<br> route,<br> service,<br> body hash,<br> query hash | Non [RFC 7519](https://tools.ietf.org/html/rfc7519) field with information about consumer, credentials, route, service and request from Kong (object).

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
      "bodyhash": "4d2c0c087cdb197604b99938e6b8fcc4226c3a75b6206954d13c843c9524f863",
      "queryhash": "1a5ab7324675b344a37e70445b587cee340a490d14e9a20ea68cd6b34009bd40"
    },
    "consumer": {
      "username": "Company A",
      "id": "e96dcb71-4322-490d-b6c6-b9ba1a24b6e3"
    },
    "credentials": {
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

If body of the HTTP request is empty, then `bodyhash` is empty string.
If query string of the HTTP request URL is empty, then `queryhash` is empty string.


## Configuration

Parameter               | Type    | Description
----------------------- | ------- | -----------
issuer                  | string  | Identifies principal that issued the JWT. Present in JWT payload if not blank
private key location    | string  | The path to your Kong's private key file (.key) to sign the JWT
public key location     | string  | The path to your Kong's X.509 public key certificate file (.crt)
key id                  | string  | A hint indicating which key the client used to generate the token signature. Present in JWT header if not blank
header                  | string  | Key of НТТР header (Authorization)
include bearer          | boolean | Controls "Bearer " + JWT or just JWT in header
exp                     | integer | Controls expiration time of token (between 0 and 86400). If 0, then `exp` field is not present in JWT payload
consumer                | array   | List of keys of **currently authenticated** consumer entity to show in kong.consumer object of JWT payload (use * to include all available keys)
credentials             | array   | List of keys of credentials of the **currently authenticated** consumer entity to show in kong.credentials object of JWT payload (use * to include all available keys)
route                   | array   | List of keys of **current** route entity to show in kong.route object of JWT payload (use * to include all available keys)
service                 | array   | List of keys of **current** service entity to show in kong.service object of JWT payload (use * to include all available keys)
x5c                     | boolean | Controls `x5c` field in JWT header
aud                     | boolean | Controls `aud` field in JWT payload
iat                     | boolean | Controls `iat` field in JWT payload
jti                     | boolean | Controls `jti` field in JWT payload
body hash               | boolean | Controls `bodyhash` field in kong.request object of JWT payload
query hash              | boolean | Controls `queryhash` field in kong.request object of JWT payload

## Private and Public RSA Keys

The plugin **requires** that Kong's private key be accessible in order to sign the JWT (configuration parameter "private key location").
X.509 public key certificate can be included in the [x5c](https://tools.ietf.org/html/rfc7515#section-4.1.6) JWT header for use by API providers to validate the JWT (configuration parameter "public key location").

#### Backwards Compatibility

To maintain backwards compatibility, support for passing the key locations through environment variables is also available.
We access these via Kong's overriding environment variables `KONG_SSL_CERT_KEY` for the private key as well as `KONG_SSL_CERT_DER` for the X.509 public key certificate.

If not already set, these can be done so as follows:
```
$ export KONG_SSL_CERT_KEY="/path/to/kong/ssl/private.key"
$ export KONG_SSL_CERT_DER="/path/to/kong/ssl/public.crt"
```

One last step is to make the environment variables accessible by an nginx worker.
To do this, simply add these line to your _nginx.conf_.
```
env KONG_SSL_CERT_KEY;
env KONG_SSL_CERT_DER;
```

#### Create Key Files with OpenSSL

The basics command line to generate a private key and X.509 public key certificate
using [OpenSSL](https://www.openssl.org) in one command:

```
openssl req -x509 -newkey rsa:2048 -keyout private.key -out public.crt -days 365 -nodes
```

It generates:

1. 2048 bits **unprotected** by passphrase private key in file _private.key_ in PEM format.
2. Self-signed X.509 public key certificate with an expiration of 365 days in file _public.crt_ in PEM format.

⚠ Self-signed certificates are **not validated** with any third party.
If you need more security, you should use a certificate signed by a [certificate authority](https://en.wikipedia.org/wiki/Certificate_authority) (CA).

## Plugin Schema Configuration

```lua
issuer = "Issuer"
private_key_location = "/home/kong/ssl/private.key"
public_key_location = "/home/kong/ssl/public.crt"
key_id = "keyId"
header = "Authorization"
include_bearer = true
exp = 60
consumer = { "id", "name" }
credentials = { "key" }
route = { "id", "name" }
service = { "id", "name" }
x5c = false
aud = false
iat = false
jti = false
body_hash = false
query_hash = false
```

## Authors and Maintainers

The original authors and maintainers of [kong-upstream-jwt](https://github.com/Optum/kong-upstream-jwt) plugin:

- [jeremyjpj0916](https://github.com/jeremyjpj0916)
- [rsbrisci](https://github.com/rsbrisci)

The author and maintainer of [kong-upstream-jwt-extended](https://github.com/andrey-tech/kong-upstream-jwt-extended) plugin:

- [andrey-tech](https://github.com/andrey-tech)

## License

This plugin is licensed under the [Apache License Version 2.0](./LICENSE).

-----------------------------------------------------------------------------------------------------------------------

<a id="russian-version"></a>

## Обзор

Данный плагин является форком плагина [kong-upstream-jwt](https://github.com/Optum/kong-upstream-jwt) и **расширяет его возможности**.

Плагин добавляет подписанный с помощью алгоритма RS256 токен типа [JSON Web Token](https://ru.wikipedia.org/wiki/JSON_Web_Token) (JWT)
([RFC 7519](https://tools.ietf.org/html/rfc7519)) в заголовок `Authorization` НТТР-запросов, прошедших через шлюз Kong,
в целях обеспечения аутентификации, авторизации и удостоверения подлинности и неоспоримости данных,
передаваемых в HTTP-запросе от шлюза Kong к API.

Зачастую API требуют средства криптографической проверки того, что полученные ими запросы, во-первых,
действительно прошли через шлюз Kong и, во-вторых, не подделаны при передаче от шлюза Kong к API.

Формируемый токен JWT позволяет выполнить обе эти проверки:

1. **Аутентификация** и **авторизация**. Обеспечивается посредством проверки подписи токена.
    API может проверить подпись токена, которая была создана с использованием закрытого RSA-ключа шлюза Kong,
    при помощи [сертификата открытого ключа X.509](https://en.wikipedia.org/wiki/X.509).
    Сертификат открытого ключа X.509 шлюза Kong может храниться в хранилище ключей, доступном API,
    или передаваться вместе с токеном в поле заголовка [`x5c`](https://tools.ietf.org/html/rfc7515#section-4.1.6),
    при обязательном условии, что API проверяет цепочку подписей по своему хранилищу доверенных сертификатов.

2. **Подлинность и неоспоримость данных**. Обеспечивается посредством хеширования тела НТТР-запроса и
    строки параметров запроса с использованием алгоритма [SHA-256](https://ru.wikipedia.org/wiki/SHA-2).
    Полученные дайджесты включаются в элементы `bodyhash` and `queryhash` поля `kong` полезной нагрузки (payload) токена.
    API может вычислить хеши тела НТТР-запроса и строки параметров запроса и сравнить их с дайджестами, полученными с
    полезной нагрузкой токена. Если они идентичны, то тело и строка параметров запроса не были изменены
    при передаче от шлюза Kong к API.

    Кроме того информация о следующих объектах (сущностях) шлюза Kong может быть включена в поле `kong` полезной
    нагрузки токена: consumer, credentials, route и service.

## Поддерживаемые релизы Kong

- Kong >= 1.0.x

## Установка

Установка из репозитория [LuaRocks](https://luarocks.org/modules/andrey-tech/kong-upstream-jwt-extended)
(рекомендуемый вариант):
```
$ luarocks install kong-upstream-jwt-extended
```

Установка из репозитория GitHub:
```
$ git clone https://github.com/andrey-tech/kong-upstream-jwt-extended.git /path/to/kong/plugins/kong-upstream-jwt-extended
$ cd /path/to/kong/plugins/kong-upstream-jwt-extended
$ luarocks make *.rockspec
```

## Токен JWT

### Заголовок (header)

Поле   | Параметр конфигурации   | Описание
-------| ----------------------- | ------------
[`typ`](https://tools.ietf.org/html/rfc7515#section-4.1.9)   |           | Тип токена (JWT)
[`alg`](https://tools.ietf.org/html/rfc7515#section-4.1.1)   |           | Алгоритм, используемый при подписании токена (RS256)
[`x5c`](https://tools.ietf.org/html/rfc7515#section-4.1.6)   | x5c       | Сертификат открытого ключа X.509, представленный в виде массива из одной строки, закодированной по стандарту [Base64](https://ru.wikipedia.org/wiki/Base64)
[`kid`](https://tools.ietf.org/html/rfc7515#section-4.1.4)   | key id    | Указывает какой именно ключ был использован для защиты токена и позволяет уведомлять об изменении ключа

Пример декодированного заголовка токена:
```json
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "key-id-001",
  "x5c": ["...X.509 public key certificate data..."]
}
```

### Полезная нагрузка (payload)

Поле   | Параметр конфигурации | Описание
-------| --------------------- | ------------
[`aud`](https://tools.ietf.org/html/rfc7519#section-4.1.3)   | aud      | Идентификатор получателя токена (имя сервиса Kong)
[`iss`](https://tools.ietf.org/html/rfc7519#section-4.1.1)   | issuer   | Идентификатор стороны, генерирующей токен
[`iat`](https://tools.ietf.org/html/rfc7519#section-4.1.6)   | iat      | Время создания токена в формате [Unix time](https://ru.wikipedia.org/wiki/Unix-%D0%B2%D1%80%D0%B5%D0%BC%D1%8F)
[`jti`](https://tools.ietf.org/html/rfc7519#section-4.1.7)   | jwt      | Уникальный идентификатор токена ([UUID](https://ru.wikipedia.org/wiki/UUID))
[`exp`](https://tools.ietf.org/html/rfc7519#section-4.1.4)   | exp      | Время когда токен станет недействительным в формате [Unix time](https://ru.wikipedia.org/wiki/Unix-%D0%B2%D1%80%D0%B5%D0%BC%D1%8F)
`kong`                                                       | consumer,<br> credentials,<br> route,<br> service,<br> body hash,<br> query hash | Поле с информацией об объектах Kong и запросе (объект)

Пример декодированной полезной нагрузки токена:
```json
{
  "aud": "Service-1",
  "iss": "issuer",
  "iat": 1550258274,
  "exp": 1550258334,
  "jti": "d4f10edb-c4f0-47d3-b7e0-90a30a885a0b",
  "kong": {
    "request": {
      "bodyhash": "4d2c0c087cdb197604b99938e6b8fcc4226c3a75b6206954d13c843c9524f863",
      "queryhash": "1a5ab7324675b344a37e70445b587cee340a490d14e9a20ea68cd6b34009bd40"
    },
    "consumer": {
      "username": "Company A",
      "id": "e96dcb71-4322-490d-b6c6-b9ba1a24b6e3"
    },
    "credentials": {
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

Если тело HTTP-запроса пусто, то дайджест тела запроса `bodyhash` - это путая строка.
Если строка параметров НТТР-запроса отсутствует, то дайджест строки параметров запроса `queryhash` - это путая строка.

## Параметры конфигурации

Параметр                | Тип     | Описание
----------------------- | ------- | -----------
issuer                  | string  | Идентификатор стороны, генерирующей токен (присутствует в полезной нагрузке токена, если не пустая строка)
private key location    | string  | Абсолютный путь к файлу (.key) на сервере Kong, содержащему закрытый ключ для подписания токена
public key location     | string  | Абсолютный путь к файлу (.crt) на сервере Kong, содержащему сертификат публичного ключа X.509
key id                  | string  | Указывает какой именно ключ был использован для защиты токена и позволяет уведомлять об изменении ключа (присутствует в заголовке токена, если не пустая строка)
header                  | string  | Имя НТТР-заголовка (`Authorization`) токена
include bearer          | boolean | Управляет добавлением строки `Bearer ` к токену в HTTP-заголовке `Authorization`
exp                     | integer | Время истечения токена в интервале между 0 и 86400 (присутствует в полезной нагрузке токена, если не 0)
consumer                | array   | Список ключей **аутентифицированного** потребителя (consumer), включаемых в объект kong.consumer в полезной нагрузке токена (если `*`, то включаются все доступные ключи)
credentials             | array   | Список ключей полномочий (credentials) **аутентифицированного** потребителя (consumer), включаемых в объект kong.credentials в полезной нагрузке токена (если `*`, то включаются все доступные ключи)
route                   | array   | Список ключей **текущего** маршрута (route), включаемых в объект kong.route в полезной нагрузке токена (если `*`, то включаются все доступные ключи)
service                 | array   | Список ключей **текущего** сервиса (service), включаемых в объект kong.service в полезной нагрузке токена (если `*`, то включаются все доступные ключи)
x5c                     | boolean | Управляет включением поля `x5c` в заголовок токена
aud                     | boolean | Управляет включением поля `aud` в полезную нагрузку токена
iat                     | boolean | Управляет включением поля `iat` в полезную нагрузку токена
jti                     | boolean | Управляет включением поля `jti` в полезную нагрузку токена
body hash               | boolean | Управляет включением поля `bodyhash` в объект kong.request в полезной нагрузке токена
query hash              | boolean | Управляет включением поля `queryhash` в объект kong.request в полезной нагрузке токена


## Закрытый и публичный ключи

Плагин **требует**, чтобы закрытый ключ был доступен для подписания токена (см. параметр конфигурации "private key location").

Сертификат публичного ключа X.509 может быть включен в поле заголовка [x5c](https://tools.ietf.org/html/rfc7515#section-4.1.6) токена
для проверки его подписи, но при обязательном условии, что API проверяет цепочку подписей по своему хранилищу доверенных сертификатов
(см. параметр конфигурации "public key location").

#### Обратная совместимость

Для обеспечения обратной совместимости, поддерживается передача абсолютных путей к файлам закрытого и открытого ключей
через переменные окружения, которые переопределяют значения, установленные в параметрах конфигурации плагина:

 - `KONG_SSL_CERT_KEY` - закрытый ключ,
 - `KONG_SSL_CERT_DER` - сертификат публичного ключа X.509.

Пример установки переменных окружения:
```
$ export KONG_SSL_CERT_KEY="/path/to/kong/ssl/private.key"
$ export KONG_SSL_CERT_DER="/path/to/kong/ssl/public.crt"
```

Для того, чтобы переменные окружения были доступны в nginx, необходимо добавить в его файл конфигурации *nginx.conf*:
```
env KONG_SSL_CERT_KEY;
env KONG_SSL_CERT_DER;
```

#### Создание ключей с помощью OpenSSL

Создание закрытого ключа и **самоподписанного** сертификата открытого ключа X.509 с использованием
утилиты [OpenSSL](https://www.openssl.org) может быть выполнено одной командой:

```
openssl req -x509 -newkey rsa:2048 -keyout private.key -out public.crt -days 365 -nodes
```

Команда выполняет:

- создание закрытого RSA-ключа длиной 2048 бит в формате PEM **не защищенного** парольной фразой в файле *private.key*:
- создание самоподписанного сертификата X.509 в формате PEM со сроком действия 365 дней в файле *public.crt*.

⚠  Самоподписанный сертификат **не проверяется** третьими лицами.
Если требуется дополнительная безопасность, то необходимо использовать сертификат открытого ключа,
подписанный [центром сертификации (CA)](https://ru.wikipedia.org/wiki/%D0%A6%D0%B5%D0%BD%D1%82%D1%80_%D1%81%D0%B5%D1%80%D1%82%D0%B8%D1%84%D0%B8%D0%BA%D0%B0%D1%86%D0%B8%D0%B8).

## Схема конфигурации плагина

```lua
issuer = "Issuer"
private_key_location = "/home/kong/ssl/private.key"
public_key_location = "/home/kong/ssl/public.crt"
key_id = "keyId"
header = "Authorization"
include_bearer = true
exp = 60
consumer = { "id", "name" }
credentials = { "key" }
route = { "id", "name" }
service = { "id", "name" }
x5c = false
aud = false
iat = false
jti = false
body_hash = false
query_hash = false
```

## Авторы

Авторы оригинального плагина [kong-upstream-jwt](https://github.com/Optum/kong-upstream-jwt):

- [jeremyjpj0916](https://github.com/jeremyjpj0916)
- [rsbrisci](https://github.com/rsbrisci)

Автор плагина [kong-upstream-jwt-extended](https://github.com/andrey-tech/kong-upstream-jwt-extended):

- [andrey-tech](https://github.com/andrey-tech)

## Лицензия

Данный плагин распространяется по лицензии [Apache License Version 2.0](./LICENSE).
