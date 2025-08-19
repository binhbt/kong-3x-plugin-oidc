local OidcHandler = {
  PRIORITY = 1000,
  VERSION = "1.1.1",
}
local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")

local lrucache = require "resty.lrucache"
local cjson = require "cjson"

-- Tạo LRU cache global, 50k phần tử (tùy chỉnh)
local introspect_cache, err = lrucache.new(50000)
if not introspect_cache then
  error("failed to create the introspect LRU cache: " .. (err or "unknown error"))
end
ngx.log(ngx.DEBUG, "[OIDC] Introspect cache created once")


-- Hàm introspect có cache
local function introspect(oidcConfig)
  ngx.log(ngx.DEBUG, "[OIDC] introspect_cache address: ", tostring(introspect_cache))

  if not (utils.has_bearer_access_token() or oidcConfig.bearer_only == "yes") then
    return nil, nil
  end

  local auth_header = ngx.req.get_headers()['Authorization']
  local token = nil
  if auth_header then
    local _, _, bearer_token = string.find(auth_header, "Bearer%s+(.+)")
    token = bearer_token
  end

  if not token then
    ngx.log(ngx.DEBUG, "[OIDC] No Bearer token found in Authorization header")
    return nil, "no token"
  end

  -- Thử lấy từ cache
  local cached = introspect_cache:get(token)
  ngx.log(ngx.DEBUG, "[OIDC] Introspection  cached: ", cached)
  if cached ~= nil then
    ngx.log(ngx.DEBUG, "[OIDC] Introspection cache HIT for token: ", token)
    return cached, nil
  end

  ngx.log(ngx.DEBUG, "[OIDC] Introspection cache MISS for token: ", token, ", calling introspect API")

  -- Gọi thật introspect API
  local res, err = require("resty.openidc").introspect(oidcConfig)
  if err then
    return nil, err
  end

  -- Cache kết quả, TTL mặc định 30s hoặc cấu hình
  local ttl = tonumber(oidcConfig.cache_ttl) or 30
  introspect_cache:set(token, res, ttl)
  ngx.log(ngx.DEBUG, "[OIDC] Introspection cache SET for token: ", token, " data: ", cjson.encode(res))
  -- local test = introspect_cache:get(token)
  -- ngx.log(ngx.DEBUG, "[OIDC] TEST GET CACHE: ", " data: ", test)

  return res, nil
end

function OidcHandler:access(config)
  local oidcConfig = utils.get_options(config, ngx)

  if filter.shouldProcessRequest(oidcConfig) then
    session.configure(config)
    handle(oidcConfig)
  else
    ngx.log(ngx.DEBUG, "[OIDC] Ignoring request, path: " .. ngx.var.request_uri)
  end

  ngx.log(ngx.DEBUG, "[OIDC] OidcHandler done")
end

function handle(oidcConfig)
  local response, err
  local has_bearer = utils.has_bearer_access_token()

  if oidcConfig.bearer_only == "yes" and has_bearer then
    if oidcConfig.introspection_endpoint then
      -- require("resty.openidc").introspect(oidcConfig)
      -- Gọi hàm introspect tự viết có cache
      response, err = introspect(oidcConfig)
    else
      response, err = require("resty.openidc").bearer_jwt_verify(oidcConfig)
    end

    if err or not response then
      ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '",error="' .. (err or "unauthorized") .. '"'
      utils.exit(ngx.HTTP_UNAUTHORIZED, err or "unauthorized", ngx.HTTP_UNAUTHORIZED)
    end

  else
    response = make_oidc(oidcConfig)
  end

  if response then
    if response.user then utils.injectUser(response.user) end
    if response.access_token then utils.injectAccessToken(response.access_token) end
    if response.id_token then utils.injectIDToken(response.id_token) end
  end
end

function make_oidc(oidcConfig)
  ngx.log(ngx.DEBUG, "[OIDC] Calling authenticate, path: " .. ngx.var.request_uri)
  local res, err = require("resty.openidc").authenticate(oidcConfig)
  if err then
    if oidcConfig.recovery_page_path then
      ngx.log(ngx.DEBUG, "[OIDC] Entering recovery page: " .. oidcConfig.recovery_page_path)
      ngx.redirect(oidcConfig.recovery_page_path)
    end
    utils.exit(500, err, ngx.HTTP_INTERNAL_SERVER_ERROR)
  end
  return res
end

return OidcHandler
