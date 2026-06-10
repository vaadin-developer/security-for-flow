/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package com.svenruppert.jsentinel.credential.propagation;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * OIDC access token. Semantically a bearer token plus a known issuer.
 * {@link #issuerHash()} is the SHA-256 hex of the issuer URL, retained
 * for audit metadata only.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public record OidcAccessToken(
    String value,
    Optional<Instant> expiresAt,
    Optional<String> audience,
    Optional<String> issuerHash)
    implements TokenCredential {

  public OidcAccessToken {
    Objects.requireNonNull(value, "value");
    if (value.isEmpty()) {
      throw new IllegalArgumentException("OidcAccessToken value must be non-empty");
    }
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(audience, "audience");
    Objects.requireNonNull(issuerHash, "issuerHash");
  }

  @Override
  public String toString() {
    return "OidcAccessToken{exp=" + expiresAt.orElse(null)
        + ", aud=" + audience.orElse(null)
        + ", iss=" + issuerHash.orElse(null)
        + ", value=***}";
  }
}
