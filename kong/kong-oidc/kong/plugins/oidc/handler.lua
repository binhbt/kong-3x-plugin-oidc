local OidcHandler = {
  PRIORITY = 1000,
  VERSION = "1.1.1",
}

local utils = require("kong.plugins.oidc.utils")
local filter = require("kong.plugins.oidc.filter")
local session = require("kong.plugins.oidc.session")
local cjson = require "cjson"

-- Sử dụng shared dict cache
local introspect_cache = ngx.shared.oidc_introspect_cache
if not introspect_cache then
  ngx.log(ngx.ERR, "[OIDC] shared dict 'oidc_introspect_cache' not found. Check KONG_NGINX_HTTP_LUA_SHARED_DICT. set ENV KONG_NGINX_HTTP_LUA_SHARED_DICT")
end

local function introspect(oidcConfig)
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

  -- Thử lấy từ shared dict cache
  local cached_json = introspect_cache:get(token)
  if cached_json then
    ngx.log(ngx.DEBUG, "[OIDC] Introspection cache HIT for token: ", token)
    local ok, cached_data = pcall(cjson.decode, cached_json)
    if ok then
      return cached_data, nil
    else
      ngx.log(ngx.ERR, "[OIDC] Failed to decode cached JSON: ", cached_json)
    end
  else
    ngx.log(ngx.DEBUG, "[OIDC] Introspection cache MISS for token: ", token)
  end

  -- Gọi thật introspect API
  local res, err = require("resty.openidc").introspect(oidcConfig)
  ngx.log(ngx.DEBUG, "[OIDC] Introspection err: ", err)
  if err then
    return nil, err
  end
  
  -- Cache kết quả dưới dạng JSON
  local ttl = tonumber(oidcConfig.cache_ttl) or 30
  local ok, json_str = pcall(cjson.encode, res)
  if ok then
    local success, set_err = introspect_cache:set(token, json_str, ttl)
    if not success then
      ngx.log(ngx.ERR, "[OIDC] Failed to set cache: ", set_err)
    else
      ngx.log(ngx.DEBUG, "[OIDC] Introspection cache SET for token: ", token)
    end
  else
    ngx.log(ngx.ERR, "[OIDC] Failed to encode JSON for cache: ", res)
  end

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

  if oidcConfig.bearer_only == "yes" then
    if not has_bearer then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '", error="missing_token"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, "missing_token", ngx.HTTP_UNAUTHORIZED)
    end

    if oidcConfig.introspection_endpoint then
        response, err = introspect(oidcConfig)
    else
        response, err = require("resty.openidc").bearer_jwt_verify(oidcConfig)
    end

    if err or not response then
        ngx.header["WWW-Authenticate"] = 'Bearer realm="' .. oidcConfig.realm .. '", error="' .. (err or "unauthorized") .. '"'
        utils.exit(ngx.HTTP_UNAUTHORIZED, err or "unauthorized", ngx.HTTP_UNAUTHORIZED)
    end
  else
    response = make_oidc(oidcConfig)
  end

  if response then
    -- Inject token fields to headers
    for k, v in pairs(response) do
        local header_name = "X-Token-" .. tostring(k):gsub("_", "-")
        if type(v) == "table" then
        -- Chuyển table thành JSON string
        ngx.req.set_header(header_name, cjson.encode(v))
        else
        ngx.req.set_header(header_name, tostring(v))
        end
    end

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
