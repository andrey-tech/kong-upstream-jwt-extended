-- © Optum 2018

-- Changed © andrey-tech 2020
local access = require "kong.plugins.kong-upstream-jwt-extended.access"

-- Changed © andrey-tech 2020
local KongUpstreamJWTExtendedHandler = {}

-- Changed © andrey-tech 2020
function KongUpstreamJWTExtendedHandler:access(conf)
  access.execute(conf)
end

-- Changed © andrey-tech 2020
KongUpstreamJWTExtendedHandler.PRIORITY = 999 -- This plugin needs to run after auth plugins for `kong.client.get_consumer(), kong.client.get_credential()`
KongUpstreamJWTExtendedHandler.VERSION = "2.1.0"

-- Changed © andrey-tech 2020
return KongUpstreamJWTExtendedHandler
