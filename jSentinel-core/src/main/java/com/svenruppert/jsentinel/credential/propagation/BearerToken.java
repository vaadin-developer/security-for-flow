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
 * Opaque bearer token, typically carried as
 * {@code Authorization: Bearer <value>}.
 *
 * <p>{@code toString()} masks {@link #value()} — see the
 * {@link TokenCredential} contract.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public record BearerToken(
    String value,
    Optional<Instant> expiresAt,
    Optional<String> audience,
    Optional<String> issuerHash)
    implements TokenCredential {

  public BearerToken {
    Objects.requireNonNull(value, "value");
    if (value.isEmpty()) {
      throw new IllegalArgumentException("BearerToken value must be non-empty");
    }
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(audience, "audience");
    Objects.requireNonNull(issuerHash, "issuerHash");
  }

  /**
   * Convenience constructor that fills the three optional fields with
   * {@link Optional#empty()}.
   */
  public BearerToken(String value) {
    this(value, Optional.empty(), Optional.empty(), Optional.empty());
  }

  /**
   * @return a redacted representation that never reveals {@link #value()}
   */
  @Override
  public String toString() {
    return "BearerToken{exp=" + expiresAt.orElse(null)
        + ", aud=" + audience.orElse(null)
        + ", value=***}";
  }
}
