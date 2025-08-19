local http = require "resty.http"
local cjson = require "cjson.safe"
local lrucache = require "resty.lrucache"

local kong = kong
local ngx = ngx

local KeycloakIntrospect = {
  VERSION = "0.1",
  PRIORITY = 1000,
}

-- Tạo cache 10.000 phần tử
local token_cache, err = lrucache.new(50000)
if not token_cache then
  error("failed to create the cache: " .. (err or "unknown error"))
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
  local cached = token_cache:get(token)
  ngx.log(ngx.DEBUG, "[INTROSPECT] cached:", cached)
  if cached ~= nil then
    kong.log.debug("[keycloak-introspect] Cache hit for token")
    if not cached.active then
      return kong.response.exit(401, { message = "Token is inactive (cached)", details = cached })
    end

    -- Set header người dùng
    for key, value in pairs(cached) do
      if type(value) == "string" or type(value) == "number" or type(value) == "boolean" then
        local header_name = "X-Token-" .. tostring(key):gsub("_", "-")
        kong.service.request.set_header(header_name, tostring(value))
      end
    end
    return
  end

  kong.log.debug("[keycloak-introspect] Cache miss. Calling introspection API.")

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

  -- Lưu cache
  local ttl = conf.cache_ttl or 30
  token_cache:set(token, body, ttl)

  if not body.active then
    return kong.response.exit(401, { message = "Token is inactive", details = body })
  end

  kong.log.debug("[keycloak-introspect] Token active. Subject: ", body.sub)


  for key, value in pairs(body) do
    if type(value) == "string" or type(value) == "number" or type(value) == "boolean" then
      local header_name = "X-Token-" .. tostring(key):gsub("_", "-")
      kong.service.request.set_header(header_name, tostring(value))
    end
  end


end


return KeycloakIntrospect
