-- © Optum 2018
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"
local singletons = require "kong.singletons"
local pl_file = require "pl.file"
local json = require "cjson"
local openssl_digest = require "resty.openssl.digest"
local openssl_pkey = require "resty.openssl.pkey"
local table_concat = table.concat
local encode_base64 = ngx.encode_base64
local env_private_key_location = os.getenv("KONG_SSL_CERT_KEY")
local env_public_key_location = os.getenv("KONG_SSL_CERT_DER")
local utils = require "kong.tools.utils"
local _M = {}

--- Get the private key location either from the environment or from configuration
-- © Optum 2018
-- @param conf the kong configuration
-- @return the private key location
local function get_private_key_location(conf)
  if env_private_key_location then
    return env_private_key_location
  end
  return conf.private_key_location
end

--- Get the public key location either from the environment or from configuration
-- © Optum 2018
-- @param conf the kong configuration
-- @return the public key location
local function get_public_key_location(conf)
  if env_public_key_location then
    return env_public_key_location
  end
  return conf.public_key_location
end

--- base 64 encoding
-- © Optum 2018
-- @param input String to base64 encode
-- @return Base64 encoded string
local function b64_encode(input)
  local result = encode_base64(input)
  result = result:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
  return result
end

--- Read contents of file from given location
-- © Optum 2018
-- @param file_location the file location
-- @return the file contents
local function read_from_file(file_location)
  local content, err = pl_file.read(file_location)
  if not content then
    ngx.log(ngx.ERR, "Could not read file contents", err)
    return nil, err
  end
  return content
end

--- Get the Kong key either from cache or the given `location`
-- © Optum 2018
-- @param key the cache key to lookup first
-- @param location the location of the key file
-- @return the key contents
local function get_kong_key(key, location)
  -- This will add a non expiring TTL on this cached value
  -- https://github.com/thibaultcha/lua-resty-mlcache/blob/master/README.md
  local pkey, err = singletons.cache:get(key, { ttl = 0 }, read_from_file, location)

  if err then
    ngx.log(ngx.ERR, "Could not retrieve pkey: ", err)
    return
  end

  return pkey
end

--- Build the body hash
-- © Optum 2018
-- @return SHA-256 hash of the request body data
local function build_body_hash()
  ngx.req.read_body()
  local req_body  = ngx.req.get_body_data()
  local body_digest = ""
  if req_body then
    local sha256 = resty_sha256:new()
    sha256:update(req_body)
    body_digest = sha256:final()
  end
  return str.to_hex(body_digest)
end

--- Build the query hash
-- Added © andrey-tech 2020
-- @return SHA-256 hash of the request query data
local function build_query_hash()
  local req_query  = kong.request.get_raw_query()
  local query_digest = ""
  if req_query then
    local sha256 = resty_sha256:new()
    sha256:update(req_query)
    query_digest = sha256:final()
  end
  return str.to_hex(query_digest)
end

--- Checks whether table contains specific value
-- Added © andrey-tech 2020
-- @param table the table
-- @param value the value to check
local function has_value(table, value)
    for _, val in ipairs(table) do
        if val == value then
            return true
        end
    end
    return false
end

--- Base64 encode the JWT token
-- © Optum 2018
-- @param payload the payload of the token
-- @param key the key to sign the token with
-- @return the encoded JWT token
local function encode_jwt_token(conf, payload, key)

  -- Changed © andrey-tech 2020
  local header = {
    typ = "JWT",
    alg = "RS256"
  }

  -- Changed © andrey-tech 2020
  if conf.x5c then
    header.x5c = {
      b64_encode(get_kong_key("pubder", get_public_key_location(conf)))
    }
  end

  if conf.key_id then
    header.kid = conf.key_id
  end

  local segments = {
    b64_encode(json.encode(header)),
    b64_encode(json.encode(payload))
  }

  local signing_input = table_concat(segments, ".")
  local digest = openssl_digest.new("sha256")
  assert(digest:update(signing_input))
  local signature = assert(openssl_pkey.new(key):sign(digest))
  -- local signature = openssl_pkey.new(key):sign(openssl_digest.new("sha256"):update(signing_input))
  segments[#segments+1] = b64_encode(signature)

  return table_concat(segments, ".")
end

--- Build the JWT token payload
-- © Optum 2018
-- @param conf the configuration
-- @return the JWT payload (table)
local function build_jwt_payload(conf)
  local current_time = ngx.time() -- Much better performance improvement over os.time()

  -- Changed © andrey-tech 2020
  local payload = {}

  -- RFC 7519 Registered Claim Names in payload

  -- Changed © andrey-tech 2020
  if conf.exp > 0 then
    payload.exp = current_time + conf.exp
  end

  -- Changed © andrey-tech 2020
  if conf.jti then
    payload.jti = utils.uuid()
  end

  -- Changed © andrey-tech 2020
  if conf.iat then
    payload.iat = current_time
  end

  -- Changed © andrey-tech 2020
  if conf.issuer then
    payload.iss = conf.issuer
  end

  if ngx.ctx.service then
    -- Changed © andrey-tech 2020
    if conf.aud then
      payload.aud = ngx.ctx.service.name
    end
  end

  -- Non RFC 7519 Claim Names in payload

  -- Added © andrey-tech 2020
  payload.kong = {}

  -- Changed © andrey-tech 2020
  if conf.body_hash then
    payload.kong.bodyhash = build_body_hash()
  end

  -- Added © andrey-tech 2020
  if conf.query_hash then
    payload.kong.queryhash = build_query_hash()
  end

  -- Added © andrey-tech © 2020
  if conf.consumer and #conf.consumer > 0 then
    payload.kong.consumer = {}
    -- Returns the consumer entity of the currently authenticated consumer. If not set yet, it returns nil.
    local consumer = kong.client.get_consumer()
    if consumer then
      if has_value(conf.consumer, "*") then
        payload.kong.consumer = consumer
      else
        for _, key in ipairs(conf.consumer) do
          payload.kong.consumer[key] = consumer[key]
        end
      end
    end
  end

  -- Added © andrey-tech © 2020
  if conf.credential and #conf.credential > 0 then
    payload.kong.credential = {}
    -- Returns the credentials of the currently authenticated consumer. If not set yet, it returns nil
    local credential = kong.client.get_credential()
    if credential then
      if has_value(conf.credential, "*") then
        payload.kong.credential = credential
      else
        for _, key in ipairs(conf.credential) do
          payload.kong.credential[key] = credential[key]
        end
      end
    end
  end

  -- Added © andrey-tech © 2020
  if conf.route and #conf.route > 0 then
    payload.kong.route = {}
    -- Returns the current route entity. The request was matched against this route.
    local route = kong.router.get_route()
    if route then
      if has_value(conf.route, "*") then
        payload.kong.route = route
      else
        for _, key in ipairs(conf.route) do
          payload.kong.route[key] = route[key]
        end
      end
    end
  end

  -- Added © andrey-tech © 2020
  if conf.service and #conf.service > 0 then
    payload.kong.service = {}
    -- Returns the current service entity. The request will be targetted to this upstream service.
    local service = kong.router.get_service()
    if service then
      if has_value(conf.service, "*") then
        payload.kong.service = service
      else
        for _, key in ipairs(conf.service) do
          payload.kong.service[key] = service[key]
        end
      end
    end
  end

  return payload
end

--- Build the header credential type
-- Changed © andrey-tech © 2020
-- @param conf the configuration
-- @param jwt JWT string
local function build_header_value(conf, jwt)
  if conf.include_bearer then
    return "Bearer " .. jwt
  else
    return jwt
  end
end

--- Add the JWT header to the request
-- © Optum 2018
-- @param conf the configuration
local function add_jwt_header(conf)
  local payload = build_jwt_payload(conf)
  local kong_private_key = get_kong_key("pkey", get_private_key_location(conf))
  local jwt = encode_jwt_token(conf, payload, kong_private_key)
  ngx.req.set_header(conf.header, build_header_value(conf, jwt))
end

--- Execute the script
-- © Optum 2018
-- @param conf kong configuration
function _M.execute(conf)
  add_jwt_header(conf)
end

return _M
