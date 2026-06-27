# mTLS Client-Authentication Setup (RFC 8705)

V00.79 adds OAuth2 **mutual-TLS client authentication** (RFC 8705): the client
authenticates to the token endpoint by presenting an X.509 client certificate at
the TLS layer, instead of (or in addition to) a client secret. This guide is the
operator-facing companion to the `MutualTls` / `MutualTlsClientConfig` API.

## Why mTLS is not a `ClientAuthentication`

mTLS operates at the **TLS handshake**, not as a token-endpoint form parameter, so
it is **not** a `ClientAuthentication` variant (that sealed type stays the five
secret/JWT-assertion methods). Instead the operator supplies a `KeyStore` and
jSentinel turns it into the `SSLContext` the `HttpClient` presents:

```java
MutualTlsClientConfig mtls = new MutualTlsClientConfig(keyStore, password, "client");
SSLContext ctx = MutualTls.sslContext(mtls);              // context protocol = TLS 1.3

// Pin enabledProtocols to forbid a TLS 1.2 downgrade (an SSLContext alone does not):
SSLParameters params = new SSLParameters();
params.setProtocols(new String[] {"TLSv1.3"});
HttpClient http = HttpClient.newBuilder().sslContext(ctx).sslParameters(params).build();

TokenEndpointClient tokens = new HttpTokenEndpointClient(tokenEndpoint, clientAuth, http);
```

> **No-downgrade:** `MutualTls.sslContext(...)` builds the context with `"TLSv1.3"`, but a
> bare `SSLContext` still permits a 1.2 negotiation. Pinning
> `SSLParameters.setProtocols("TLSv1.3")` on the `HttpClient` (above) is what actually
> forbids the downgrade — required for the FIPS profile.

jSentinel never loads the client key from a hardware token or OS keychain — the
operator pre-loads the `KeyStore` (Konzept §4.5).

## Preparing the client KeyStore

Use a PKCS#12 keystore holding the client certificate + private key under a known
alias. A self-signed example (replace with your CA-issued material in production):

```bash
keytool -genkeypair -alias client -keyalg RSA -keysize 2048 \
        -dname "CN=my-rp" -validity 365 \
        -keystore client.p12 -storetype PKCS12 \
        -storepass "$PW" -keypass "$PW"
```

Constraints (FIPS profile — see [`fips-profile.md`](fips-profile.md)):

- Key type **RSA-2048+** or **EC P-256**.
- The keystore **must** contain a *key entry* under the configured alias —
  `MutualTls.sslContext` raises `oauth2/mtls-keystore-empty` otherwise.
- The connection is **TLS 1.3 only**; the provider's mTLS endpoint must support it.

## `mtls_endpoint_aliases`

When the provider's discovery document advertises `mtls_endpoint_aliases`
(RFC 8705 §5), the mTLS client **must** use the aliased endpoints (they enforce
client-cert binding) rather than the plain ones:

```java
URI tokenUri = MutualTls.endpointAlias(metadata.mtlsEndpointAliases(),
                                       "token_endpoint", plainTokenEndpoint);
```

## Certificate-bound access tokens

RFC 8705 §3 binds the issued access token to the client certificate
(`cnf.x5t#S256`). Resource servers that enforce this compare the presented client
cert thumbprint against the token's `cnf`. jSentinel's mTLS support covers the
**client** side (presenting the cert); confirming `cnf.x5t#S256` at a resource
server is the resource server's responsibility.

## Checklist

- [ ] Client `KeyStore` (PKCS#12) holds an RSA-2048+/P-256 key entry under the alias.
- [ ] Keystore password supplied out-of-band (never logged; `MutualTlsClientConfig`
      defensively copies and the SSLContext build zeroes its copy).
- [ ] Provider token endpoint supports TLS 1.3 + client-cert auth.
- [ ] `mtls_endpoint_aliases` honoured when present.
- [ ] CA-issued (not self-signed) certificate in production.
