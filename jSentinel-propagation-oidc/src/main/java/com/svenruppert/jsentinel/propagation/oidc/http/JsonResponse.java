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
package com.svenruppert.jsentinel.propagation.oidc.http;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Minimal JSON extractor for the Token-Endpoint response shape
 * {@code { "access_token": "...", "token_type": "Bearer",
 * "expires_in": 3600 }}. Avoids pulling in a third-party JSON library
 * — the V00.74 contract limits the parsed surface to these three
 * fields.
 *
 * @since 00.74.00
 */
public final class JsonResponse {

  private static final Pattern ACCESS_TOKEN_RE = Pattern.compile(
      "\"access_token\"\\s*:\\s*\"([^\"]+)\"");
  private static final Pattern EXPIRES_IN_RE = Pattern.compile(
      "\"expires_in\"\\s*:\\s*(\\d+)");
  private static final Pattern TOKEN_TYPE_RE = Pattern.compile(
      "\"token_type\"\\s*:\\s*\"([^\"]+)\"");

  private JsonResponse() {
    throw new AssertionError("no instances");
  }

  /**
   * @return the {@code access_token} value or empty if absent /
   *         malformed
   */
  public static Optional<String> accessToken(String body) {
    Matcher m = ACCESS_TOKEN_RE.matcher(body);
    return m.find() ? Optional.of(m.group(1)) : Optional.empty();
  }

  /**
   * @return the {@code expires_in} value in seconds, or empty if absent or
   *     malformed. A digit run longer than {@code long} (the regex matches
   *     {@code \\d+} with no length bound) would otherwise overflow
   *     {@link Long#parseLong}; that is treated as "no usable value" rather
   *     than propagating a {@link NumberFormatException} to the caller
   *     (V00.75.10, H4).
   */
  public static Optional<Long> expiresIn(String body) {
    Matcher m = EXPIRES_IN_RE.matcher(body);
    if (!m.find()) {
      return Optional.empty();
    }
    try {
      return Optional.of(Long.parseLong(m.group(1)));
    } catch (NumberFormatException overflow) {
      return Optional.empty();
    }
  }

  /**
   * @return the {@code token_type} value (typically {@code "Bearer"})
   */
  public static Optional<String> tokenType(String body) {
    Matcher m = TOKEN_TYPE_RE.matcher(body);
    return m.find() ? Optional.of(m.group(1)) : Optional.empty();
  }
}
