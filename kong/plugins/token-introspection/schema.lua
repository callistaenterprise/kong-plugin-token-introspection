local typedefs = require "kong.db.schema.typedefs"
local url = require "socket.url"
local function validate_url(value)
  local parsed_url = url.parse(value)
  if parsed_url and parsed_url.scheme and parsed_url.host then
    parsed_url.scheme = parsed_url.scheme:lower()
    if not (parsed_url.scheme == "http" or parsed_url.scheme == "https") then
      return false, "Supported protocols are HTTP and HTTPS"
    end
  end

  return true
end

return {
  name = "token-introspection",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          { introspection_endpoint = { type = "string", required = true, custom_validator = validate_url } },
          { introspection_ssl_verify = { type = "boolean", required = true, default = true } },
          { client_id = { type = "string", required = true } },
          { client_secret = { type = "string", required = true } },
          { token_header = { type = "string", required = true, default = "Authorization" } },
          { hide_credentials = { type = "boolean", required = true, default = true } },
          { allow_anonymous = { type = "boolean", required = true, default = false } },
          { ttl = { type = "number", required = true, default = 30 } },
          { scope = { type = "array", elements = { type = "string" }, required = false } },
          { certificate_header = { type = "string", required = false } },
          { custom_claims_forward = { type = "array", elements = { type = "string" }, required = false } }
        }
      }
    }
  }
}
