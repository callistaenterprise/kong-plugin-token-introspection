local BasePlugin = require "kong.plugins.base_plugin"
local utils = require("kong.plugins.token-introspection.utils")
local http = require "resty.http"
local x509 = require "resty.openssl.x509"
local b64 = require("ngx.base64")
local cjson = require "cjson.safe"

-- issue token introspection request
local function do_introspect_access_token(access_token, config)
  local res, err = http:new():request_uri(config.introspection_endpoint, {
    ssl_verify = config.introspection_ssl_verify,
    method = "POST",
    body = "token_type_hint=access_token&token=" .. access_token
        .. "&client_id=" .. config.client_id
        .. "&client_secret=" .. config.client_secret,
    headers = { ["Content-Type"] = "application/x-www-form-urlencoded" }
  })

  if not res then
    return nil, err
  end
  if res.status ~= 200 then
    return { status = res.status }
  end
  return { status = res.status, body = res.body }
end

-- get cached token introspection result if available, or retrieve new token introspection result
local function introspect_access_token(access_token, config)
  if config.ttl > 0 then
    local res, err = kong.cache:get(access_token, { ttl = config.ttl },
        do_introspect_access_token, access_token, config)
    if err then
      kong.cache:invalidate(access_token)
      utils.exit(ngx.HTTP_INTERNAL_SERVER_ERROR, "Unexpected error: " .. err)
    end
    if res.status ~= 200 then
      kong.cache:invalidate(access_token)
    end
    return res
  else
    return do_introspect_access_token(access_token, config)
  end
end

-- get sha256 digest from uri-encoded pem certificate
local function get_digest(encoded_certificate)
  local pem, err = ngx.unescape_uri(encoded_certificate)
  if err then
    return nil, "invalid certificate: " .. err
  end
  local certificate, err = x509.new(pem, "PEM")
  if err then
    return nil, "invalid certificate: " .. err
  end
  local digest, err = certificate:digest("SHA256")
  if err then
    return nil, "cannot create digest: " .. err
  end
  return digest
end

-- verify that client certificate digest matches digest from bounded access token
local function verify_certificate(encoded_digest, certificate_header)
  local required_digest, err = b64.decode_base64url(encoded_digest)
  if err then
    return false
  end
  if not certificate_header then
    return false
  end
  local certificate = utils.get_header(certificate_header)
  if not certificate then
    return false
  end
  local digest, err = get_digest(certificate)
  if err then
    return false
  end
  return required_digest == digest
end

-- verify that access token contains required scopes
local function verify_scope(required_scope, scope)
  local scopeSet = utils.as_set(scope)
  for _, required in ipairs(required_scope) do
    if not scopeSet[required] then
      return false
    end
  end
  return true
end

local TokenIntrospection = BasePlugin:extend()

function TokenIntrospection:new()
  TokenIntrospection.super.new(self, "token-introspection")
end

function TokenIntrospection:access(config)
  TokenIntrospection.super.access(self)
  local bearer_token = utils.get_header(config.token_header)
  if not bearer_token then
    utils.exit(ngx.HTTP_UNAUTHORIZED, "Unauthenticated.")
  end
  -- remove Bearer prefix
  local access_token, removed = string.gsub(bearer_token, "Bearer ", "", 1)
  if removed == 0 then
    utils.exit(ngx.HTTP_UNAUTHORIZED, "Unauthenticated.")
  end
  -- introspect and validate token
  local introspection_response, err = introspect_access_token(access_token, config)
  if not introspection_response then
    utils.exit(ngx.HTTP_INTERNAL_SERVER_ERROR, "Authorization server error: " .. err)
  end
  if introspection_response.status ~= 200 then
    utils.exit(ngx.HTTP_UNAUTHORIZED, "The resource owner or authorization server denied the request.")
  end
  -- decode into jwt token
  local jwt = cjson.decode(introspection_response.body)
  if not jwt.active then
    utils.exit(ngx.HTTP_UNAUTHORIZED, "The resource owner or authorization server denied the request.")
  end
  -- If token is bound to client certificate, validate the binding
  if jwt.cnf and jwt.cnf["x5t#S256"] then
    if not config.certificate_header or not verify_certificate(jwt.cnf["x5t#S256"], config.certificate_header) then
      utils.exit(ngx.HTTP_UNAUTHORIZED, "The resource owner or authorization server denied the request.")
    end
  end
  -- If specific scopes are required, validate that the token contains the required scopes
  if config.scope then
    if not verify_scope(config.scope, jwt.scope) then
      utils.exit(ngx.HTTP_FORBIDDEN, "The resource owner or authorization server denied the request.")
    end
  end
  -- Authorization successful, set headers based on information from access token
  utils.set_header("X-Credential-Scope", jwt.scope)
  utils.set_header("X-Credential-Client-ID", jwt.clientId)
  utils.set_header("X-Credential-Token-Type", jwt.typ)
  utils.set_header("X-Credential-Exp", jwt.exp)
  utils.set_header("X-Credential-Iat", jwt.iat)
  utils.set_header("X-Credential-Nbf", jwt.nbf)
  utils.set_header("X-Credential-Sub", jwt.sub)
  utils.set_header("X-Credential-Aud", jwt.aud)
  utils.set_header("X-Credential-Iss", jwt.iss)
  utils.set_header("X-Credential-Jti", jwt.jti)
  if config.custom_claims_forward then
    for _, claim in ipairs(config.custom_claims_forward) do
      utils.set_header("X-Credential-" .. claim, jwt[claim])
    end
  end
  -- Optionally remove token and certificate headers
  if config.hide_credentials then
    utils.clear_header(config.token_header)
    utils.clear_header(config.certificate_header)
  end
end

return TokenIntrospection