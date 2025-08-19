local typedefs = require "kong.db.schema.typedefs"

return {
  name = "keycloak-introspect",
  fields = {
    { config = {
      type = "record",
      fields = {
        { introspection_url = { type = "string", required = true } },
        { client_id         = { type = "string", required = true } },
        { client_secret     = { type = "string", required = true } },
        { cache_ttl         = { type = "number", default = 30 } },
      },
    }, },
  },
}

