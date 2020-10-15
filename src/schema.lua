-- © Optum 2020
local typedefs = require "kong.db.schema.typedefs"

return {
    name = "kong-upstream-jwt-extended",
    fields = {
        { protocols = typedefs.protocols_http },
        { config = {
            type = "record",
            fields = {
                -- © Optum 2020
                { issuer = { type = "string", required = false }, },
                { private_key_location = { type = "string", required = false }, },
                { public_key_location = { type = "string", required = false }, },
                { key_id = { type = "string", required = false }, },
                { header = { type = "string", default = "Authorization" }, },

                -- Changed © andrey-tech 2020
                { include_bearer = { type = "boolean", default = true }, },

                -- Added © andrey-tech 2020
                { exp = { type = "number", default = 60, between = { 0, 86400 }  }, },
                { consumer = { type = "array", elements = { type = "string" }, required = false }, },
                { credentials = { type = "array", elements = { type = "string" }, required = false }, },
                { route = { type = "array", elements = { type = "string" }, required = false }, },
                { service = { type = "array", elements = { type = "string" }, required = false }, },
                { x5c = { type = "boolean", default = false }, },
                { aud = { type = "boolean", default = false }, },
                { iat = { type = "boolean", default = false }, },
                { jti = { type = "boolean", default = false }, },
                { body_hash = { type = "boolean", default = false }, },
                { query_hash = { type = "boolean", default = false }, }
            },
        }, },
    },
}
