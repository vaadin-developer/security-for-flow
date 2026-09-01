# 5-Minute Setup — Token Propagation

When a Vaadin or REST front end calls a downstream service, that call
needs the caller's identity. The usual answer is to thread a token
parameter through every method and concatenate `"Bearer " + token` at
each call site — which spreads credential handling across the codebase
and makes swapping the mechanism a refactor.

Token propagation moves that decision to one place. Annotate the
outbound interface, and a strategy resolves the header before each call.
Switching from forwarding the token to exchanging it for an audience-
scoped one becomes a bootstrap change, not a code change.

The surface is **stable as of V00.83**.

## 1. Dependency

```xml
<dependency>
  <groupId>eu.jsentinel</groupId>
  <artifactId>jCustos-propagation</artifactId>
  <version>${jcustos.version}</version>
</dependency>
```

For token exchange and client-credentials flows, add the optional
`jCustos-propagation-oidc` module.

## 2. Annotate the outbound interface

```java
@PropagateToken(service = "documents-api")
public interface DocumentGateway {

  Optional<String> fetch(String id);

  void archive(String id);
}
```

No token parameter. The annotation is class-level here, so it covers
every method; a method-level annotation overrides it, the same
resolution rule `@RequiresRole` uses.

## 3. Apply the bound header in the implementation

```java
final class HttpDocumentGateway implements DocumentGateway {

  @Override
  public Optional<String> fetch(String id) {
    HttpRequest.Builder builder = HttpRequest.newBuilder()
        .uri(URI.create(BASE_URL + "/documents/" + id))
        .GET();

    Optional<HeaderValue> header = OutboundHeaderContext.current();
    if (header.isEmpty()) {
      return Optional.empty();   // no usable credential — skip the call
    }
    builder.header(header.get().name(), header.get().value());
    ...
  }
}
```

The implementation never reads the session and never names
`Authorization`. It applies whatever the strategy bound, which is what
makes the mechanism swappable.

## 4. Wrap once, at construction

```java
DocumentGateway gateway =
    PropagatingProxy.wrap(DocumentGateway.class, new HttpDocumentGateway());
```

The proxy runs the annotation scanner per call, resolves the named
strategy, binds the header into `OutboundHeaderContext`, and clears it
afterwards so nothing leaks into the next call.

## 5. Configure the bootstrap

```java
VaadinSecurity.bootstrap()
    .authentication(authn)
    .authorization(authz)
    .propagation(p -> p
        .credentialStore(new VaadinSessionTokenCredentialStore())
        .passThrough())
    .install();
```

`credentialStore(...)` says where the inbound token lives.
`passThrough()` forwards it unchanged as a `Bearer` header — the right
default when the downstream service trusts the same issuer.

Adapter-specific stores ship with each adapter:
`VaadinSessionTokenCredentialStore` for Vaadin,
`ThreadLocalTokenCredentialStore` for REST and standalone.

## 6. Bind the token at login

```java
JCustosServiceResolver.tokenCredentialStore()
    .bind(new BearerToken(token));
```

Clear it on logout with `.clear()`.

## 7. Beyond pass-through

Register additional strategies by name and select them per call:

```java
.propagation(p -> p
    .credentialStore(store)
    .strategy("exchange", new TokenExchangeStrategy(config)))
```

```java
@PropagateToken(strategy = "exchange", audience = "billing-api")
public interface BillingGateway { ... }
```

`TokenExchangeStrategy` (RFC 8693) mints an audience-scoped token and
caches it; `ClientCredentialsStrategy` drops the caller's identity in
favour of a service identity. Both live in `jCustos-propagation-oidc`.
An unregistered strategy name binds no header and reports the
`propagation/unknown-strategy` diagnostic rather than failing the call.

## 8. Reference implementation

`demo-jcustos-vaadin-rest-client` runs this end to end:
`BackendGateway` is the annotated interface, `HttpBackendGateway`
applies the bound header, and `BackendGatewayPropagationTest` pins the
behaviour — including that the context is cleared after each call.

## Discipline

`TokenCredential#value()` is the raw token. It is never logged, never
persisted, never audited; every record subtype masks it in
`toString()`. Keep that discipline in your own strategies.
