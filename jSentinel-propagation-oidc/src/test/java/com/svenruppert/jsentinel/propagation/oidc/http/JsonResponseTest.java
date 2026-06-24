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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JsonResponse.expiresIn — overflow guard (H4)")
class JsonResponseTest {

  @Test
  @DisplayName("a normal value parses")
  void normalValue() {
    assertEquals(Optional.of(3600L),
        JsonResponse.expiresIn("{\"expires_in\":3600}"));
  }

  @Test
  @DisplayName("a missing field yields empty")
  void missingField() {
    assertTrue(JsonResponse.expiresIn("{\"token_type\":\"Bearer\"}").isEmpty());
  }

  @Test
  @DisplayName("an overlong digit run yields empty instead of throwing")
  void overflowYieldsEmpty() {
    // 30 digits — far beyond Long.MAX_VALUE; the regex matches \\d+ with no bound.
    assertTrue(JsonResponse.expiresIn(
        "{\"expires_in\":999999999999999999999999999999}").isEmpty(),
        "an out-of-range expires_in must degrade to empty, not throw");
  }
}
