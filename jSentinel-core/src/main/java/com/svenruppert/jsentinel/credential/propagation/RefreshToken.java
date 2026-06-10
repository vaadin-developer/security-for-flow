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
 * Refresh token. Class-A secret — never forwarded by
 * {@code PassThroughStrategy}.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public record RefreshToken(
    String value,
    Optional<Instant> expiresAt,
    Optional<String> audience,
    Optional<String> issuerHash)
    implements TokenCredential {

  public RefreshToken {
    Objects.requireNonNull(value, "value");
    if (value.isEmpty()) {
      throw new IllegalArgumentException("RefreshToken value must be non-empty");
    }
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(audience, "audience");
    Objects.requireNonNull(issuerHash, "issuerHash");
  }

  @Override
  public String toString() {
    return "RefreshToken{exp=" + expiresAt.orElse(null)
        + ", value=***}";
  }
}
