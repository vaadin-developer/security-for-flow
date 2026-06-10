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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("TokenCredential — toString() masks the raw value")
class TokenCredentialToStringTest {

  private static final String SECRET = "super-secret-token-value-123";

  @Test
  @DisplayName("BearerToken.toString() does not contain the raw value")
  void bearerTokenMasksValue() {
    BearerToken token = new BearerToken(SECRET,
        Optional.of(Instant.parse("2030-01-01T00:00:00Z")),
        Optional.of("api.example.com"),
        Optional.empty());
    String s = token.toString();
    assertFalse(s.contains(SECRET),
        "toString() must NOT contain the raw token: " + s);
    assertTrue(s.contains("value=***"),
        "toString() must contain the redaction marker: " + s);
  }

  @Test
  @DisplayName("OidcAccessToken.toString() does not contain the raw value")
  void oidcAccessTokenMasksValue() {
    OidcAccessToken token = new OidcAccessToken(SECRET,
        Optional.empty(),
        Optional.of("api"),
        Optional.of("a1b2c3"));
    String s = token.toString();
    assertFalse(s.contains(SECRET));
    assertTrue(s.contains("value=***"));
  }

  @Test
  @DisplayName("RefreshToken.toString() does not contain the raw value")
  void refreshTokenMasksValue() {
    RefreshToken token = new RefreshToken(SECRET,
        Optional.of(Instant.parse("2031-01-01T00:00:00Z")),
        Optional.empty(),
        Optional.empty());
    String s = token.toString();
    assertFalse(s.contains(SECRET));
    assertTrue(s.contains("value=***"));
  }

  @Test
  @DisplayName("ApiKey.toString() does not contain the raw value")
  void apiKeyMasksValue() {
    ApiKey token = new ApiKey(SECRET,
        Optional.empty(),
        Optional.of("svc"),
        Optional.empty());
    String s = token.toString();
    assertFalse(s.contains(SECRET));
    assertTrue(s.contains("value=***"));
  }
}
