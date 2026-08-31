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
package eu.jsentinel.jcustos.credential.propagation;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * Opaque API key. Never prefixed with {@code Bearer } by
 * {@code PassThroughStrategy} — consumers register their own header
 * strategy if they want one.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public record ApiKey(
    String value,
    Optional<Instant> expiresAt,
    Optional<String> audience,
    Optional<String> issuerHash)
    implements TokenCredential {

  public ApiKey {
    Objects.requireNonNull(value, "value");
    if (value.isEmpty()) {
      throw new IllegalArgumentException("ApiKey value must be non-empty");
    }
    Objects.requireNonNull(expiresAt, "expiresAt");
    Objects.requireNonNull(audience, "audience");
    Objects.requireNonNull(issuerHash, "issuerHash");
  }

  @Override
  public String toString() {
    return "ApiKey{exp=" + expiresAt.orElse(null)
        + ", aud=" + audience.orElse(null)
        + ", value=***}";
  }
}
