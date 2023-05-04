# Kong access token introspection plugin
Simple kong plugin that validates access tokens sent by developers using a third-party OAuth 2.0
Authorization Server by leveraging its introspection endpoint ([RFC7662](https://tools.ietf.org/html/rfc7662)).
The implementation is heavily inspired by [VentaApps/kong-token-introspection](https://github.com/VentaApps/kong-token-introspection).

The plugin protects an API using introspection of an OAuth 2.0 Access Token,
retrieved from a request header. It uses the introspection
endpoint ([RFC7662](https://tools.ietf.org/html/rfc7662#section-2)) of a configured third-party
OAuth 2.0 server, and optionally caches the introspection result. Specific scopes can be specified
to be required in the access token. If access is granted, key attributes from the access token are
injected as http headers for the upstream service.

If the access-token is bound to a Client Certificate ([RFC8705](https://www.rfc-editor.org/rfc/rfc8705.html)),
the sha256 fingerprint specified in the access-token must match the sha256 fingerprint of a
provided client certificate from another http header. The client certificate should be retrieved
by e.g. the [mtls-auth](https://github.com/callistaenterprise/kong-plugin-mtls-auth) plugin.

# Configuration

| Parameter                  | default       | description                                                                                                                                                             |
|----------------------------|---------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `introspection_endpoint`   |               | External introspection endpoint compatible with RFC7662                                                                                                                 |
| `introspection_ssl_verify` | true          | A boolean indicating whether to validate OAuth 2.0 introspection server certificate, if https/ssl is used                                                               |
| `client_id`                |               | Client id used when calling introspection endpoint                                                                                                                      |
| `client_secret`            |               | Client secret used when calling introspection endpoint                                                                                                                  |
| `token_header`             | Authorization | Name of api-request header containing access token                                                                                                                      |
| `hide_credentials`         | true          | A boolean indicating whether to remove the `token_header` and `certificate_header` from the request before forwarding to the upstream API                               |
| `allow_anonymous`          | false         | A boolean indicating whether to allow anonymous requests. If allowed and no access token is provided, the `X-Anonymous` header is set to true                           |
| `ttl`                      | 30            | Cache TTL (in seconds) for every token introspection result (0 - no cache)                                                                                              |
| `scope`                    |               | A list of scopes that the access token must have in order to get access. Allow any scope if empty                                                                       |
| `certificate_header`       |               | Name of request header containing client certificate to match against certificate digest claim in access token as specified by RFC8705                                  |
| `custom_claims_forward`    |               | A list of custom claims to be forwarded from the introspection response to the upstream request. Claims are forwarded in headers with prefix X-Credential-{claim-name}. |

# Upstream headers

When a request has been authenticated, the plugin appends the following headers to the request
before proxying it to the upstream API.

| Header                    | description                                                          |
|---------------------------|----------------------------------------------------------------------|
| `X-Anonymous`             | set to true if access token is missing, and `allow_anonymous`is true |
| `X-Credential-Scope`      | as returned by the Introspection response (if any)                   |
| `X-Credential-Client-ID`  | as returned by the Introspection response (if any)                   |
| `X-Credential-Token-Type` | as returned by the Introspection response (if any)                   |
| `X-Credential-Exp`        | as returned by the Introspection response (if any)                   |
| `X-Credential-Iat`        | as returned by the Introspection response (if any)                   |
| `X-Credential-Nbf`        | as returned by the Introspection response (if any)                   |
| `X-Credential-Sub`        | as returned by the Introspection response (if any)                   |
| `X-Credential-Aud`        | as returned by the Introspection response (if any)                   |
| `X-Credential-Iss`        | as returned by the Introspection response (if any)                   |
| `X-Credential-Jti`        | as returned by the Introspection response (if any)                   |

Additionally, any claims specified in `custom_claims_forward` are also forwarded with the `X-Credential-` prefix.

# Example configuration

```
- name: access-token-mtls
  host:  upstream
  port: 80
  protocol: http
  plugins: 
  - name: mtls-auth
    config:
      upstream_cert_header: "x-client-cert"
  - name: token-introspection
    config:
      introspection_endpoint: https://host.docker.internal:9443/realms/test/protocol/openid-connect/token/introspect
      client_id: introspection-client
      client_secret: secret
      certificate_header: "x-client-cert"
  routes:
  - name: access-token-mtls-route
    paths:
    - /token-mtls/
    strip_path: true
```

# Configuring trust chain for introspection endpoint

If the OAuth 2.0 introspection endpoint uses SSL using a custom PKI and
`config.introspection_ssl_verify` is `true`, the trusted CA certificates and possibly also a
certificate chain depth must be configured (see https://docs.konghq.com/gateway/latest/reference/configuration/#lua_ssl_trusted_certificate).

The following config in `kong.conf` configures the Resty http(s) client to use a self-signed PKI:

```
lua_ssl_trusted_certificate = /etc/kong/ssl/CA/localCA.crt
lua_ssl_verify_depth = 2
```
