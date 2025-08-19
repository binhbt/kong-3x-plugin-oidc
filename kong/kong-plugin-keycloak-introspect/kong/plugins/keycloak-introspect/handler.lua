local http = require "resty.http"
local cjson = require "cjson.safe"

local kong = kong
local ngx = ngx

local KeycloakIntrospect = {
  VERSION = "0.1",
  PRIORITY = 1000,
}

-- Lấy shared dict
local shared_cache = ngx.shared.oidc_introspect_cache
if not shared_cache then
  error("[keycloak-introspect] shared dict 'oidc_introspect_cache' not found. Check nginx.conf or Docker env.")
end

function KeycloakIntrospect:access(conf)
  local auth = kong.request.get_header("Authorization")
  if not auth or not auth:match("^Bearer%s+") then
    return kong.response.exit(401, { message = "Missing or invalid Authorization header" })
  end

  local token = auth:match("Bearer%s+(.+)")
  if not token then
    return kong.response.exit(401, { message = "Invalid token format" })
  end

  -- Kiểm tra cache
  local cached_json = shared_cache:get(token)
  ngx.log(ngx.DEBUG, "[INTROSPECT] cached:", cached_json)
  if cached_json then
    local cached = cjson.decode(cached_json)
    kong.log.debug("[keycloak-introspect] Cache HIT for token")
    if not cached.active then
      return kong.response.exit(401, { message = "Token is inactive (cached)", details = cached })
    end

    -- Set headers
    for key, value in pairs(cached) do
      if type(value) == "string" or type(value) == "number" or type(value) == "boolean" then
        local header_name = "X-Token-" .. tostring(key):gsub("_", "-")
        kong.service.request.set_header(header_name, tostring(value))
      end
    end

    return
  end

  kong.log.debug("[keycloak-introspect] Cache MISS. Calling introspection API.")

  local httpc = http.new()
  httpc:set_timeout(3000)

  local credentials = ngx.encode_base64(conf.client_id .. ":" .. conf.client_secret)

  local res, err = httpc:request_uri(conf.introspection_url, {
    method = "POST",
    body = "token=" .. token,
    headers = {
      ["Content-Type"] = "application/x-www-form-urlencoded",
      ["Authorization"] = "Basic " .. credentials,
    },
    ssl_verify = false, -- Bật true trong môi trường production
  })

  if not res then
    kong.log.err("[keycloak-introspect] Introspection request failed: ", err)
    return kong.response.exit(500, { message = "Introspection request failed", error = err })
  end

  local ok, body = pcall(cjson.decode, res.body)
  if not ok or not body then
    kong.log.err("[keycloak-introspect] Failed to decode response body")
    return kong.response.exit(500, { message = "Failed to parse introspection response", raw = res.body })
  end

  if res.status ~= 200 then
    return kong.response.exit(res.status, {
      message = "Failed to introspect token",
      details = body,
    })
  end

  -- Cache response (dù là active hay inactive)
  local ttl = conf.cache_ttl or 30
  local body_json = cjson.encode(body)
  local success, err, forcible = shared_cache:set(token, body_json, ttl)
  if not success then
    kong.log.err("[keycloak-introspect] Failed to cache token: ", err)
  end

  if not body.active then
    return kong.response.exit(401, { message = "Token is inactive", details = body })
  end

  kong.log.debug("[keycloak-introspect] Token active. Subject: ", body.sub)

  -- Forward headers
  for key, value in pairs(body) do
    if type(value) == "string" or type(value) == "number" or type(value) == "boolean" then
      local header_name = "X-Token-" .. tostring(key):gsub("_", "-")
      kong.service.request.set_header(header_name, tostring(value))
    end
  end
end

return KeycloakIntrospect
