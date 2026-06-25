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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("TokenCredential — record equality + validation")
class TokenCredentialEqualityTest {

  @Test
  @DisplayName("BearerToken with identical fields are equal")
  void bearerTokenEquality() {
    BearerToken a = new BearerToken("abc",
        Optional.of(Instant.parse("2030-01-01T00:00:00Z")),
        Optional.of("api"), Optional.empty());
    BearerToken b = new BearerToken("abc",
        Optional.of(Instant.parse("2030-01-01T00:00:00Z")),
        Optional.of("api"), Optional.empty());
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
  }

  @Test
  @DisplayName("BearerToken with different value is not equal")
  void bearerTokenInequality() {
    BearerToken a = new BearerToken("abc");
    BearerToken b = new BearerToken("xyz");
    assertNotEquals(a, b);
  }

  @Test
  @DisplayName("Empty value rejected on every record")
  void emptyValueRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> new BearerToken("", Optional.empty(), Optional.empty(), Optional.empty()));
    assertThrows(IllegalArgumentException.class,
        () -> new OidcAccessToken("", Optional.empty(), Optional.empty(), Optional.empty(),
            Optional.empty()));
    assertThrows(IllegalArgumentException.class,
        () -> new RefreshToken("", Optional.empty(), Optional.empty(), Optional.empty()));
    assertThrows(IllegalArgumentException.class,
        () -> new ApiKey("", Optional.empty(), Optional.empty(), Optional.empty()));
  }

  @Test
  @DisplayName("Null optional fields are rejected")
  void nullOptionalsRejected() {
    assertThrows(NullPointerException.class,
        () -> new BearerToken("v", null, Optional.empty(), Optional.empty()));
    assertThrows(NullPointerException.class,
        () -> new BearerToken("v", Optional.empty(), null, Optional.empty()));
    assertThrows(NullPointerException.class,
        () -> new BearerToken("v", Optional.empty(), Optional.empty(), null));
  }
}
