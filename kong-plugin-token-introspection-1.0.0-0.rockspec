local plugin_name = "token-introspection"
local package_name = "kong-plugin-"..plugin_name
local package_version = "1.0.0"
local rockspec_revision = "0"

package = package_name
version = package_version .. "-" .. rockspec_revision
supported_platforms = { "linux", "macosx" }

source = {
  url = "git://github.com/callistaenterprise/kong-plugin-token-introspection",
  tag = "v1.0.0",
  dir = "kong-plugin-mtls-auth"
}

description = {
   summary = "Kong Gateway plugin used to authenticate clients using OAuth 2.0 token introspection.",
   detailed = [[
This plugin is protecting Kong API service/route with introspection of OAuth2.0 access-token,
accessed from a request header. Plugin does a pre-request to oauth introspection
endpoint([RFC7662](https://tools.ietf.org/html/rfc7662#section-2)), and optionally caches
the result. A specific scope can be specified to be required in the access token.
If access is granted, information from the access token can be injected as http headers
for the upstream service.

If the access-token is bound to a Client Certificate ([RFC8705](https://www.rfc-editor.org/rfc/rfc8705.html)),
the sha256 fingerprint specified in the access-token must match the sha256 fingerprint of a
provided client certificate from another http header. The client certificate could be retrieved
by e.g. the [mtls-auth](https://github.com/callistaenterprise/kong-plugin-mtls-auth) plugin.]],
   homepage = "https://github.com/VentaApps/kong-token-introspection",
   license = "Apache 2.0"
}

dependencies = {
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins."..plugin_name..".handler"] = "kong/plugins/"..plugin_name.."/handler.lua",
    ["kong.plugins."..plugin_name..".schema"] = "kong/plugins/"..plugin_name.."/schema.lua",
    ["kong.plugins."..plugin_name..".utils"] = "kong/plugins/"..plugin_name.."/utils.lua",
  }
}
