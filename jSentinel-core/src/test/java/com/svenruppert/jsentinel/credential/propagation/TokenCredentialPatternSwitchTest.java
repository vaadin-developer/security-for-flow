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

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("TokenCredential — sealed pattern switch")
class TokenCredentialPatternSwitchTest {

  /**
   * Exhaustive pattern switch. The compiler accepts this without a
   * default branch because {@link TokenCredential} is sealed.
   */
  private static String label(TokenCredential c) {
    return switch (c) {
      case BearerToken b -> "bearer";
      case OidcAccessToken o -> "oidc";
      case RefreshToken r -> "refresh";
      case ApiKey a -> "api-key";
    };
  }

  @Test
  @DisplayName("Each permit is reachable through the sealed switch")
  void eachPermitReached() {
    assertEquals("bearer", label(new BearerToken("a")));
    assertEquals("oidc", label(new OidcAccessToken("b",
        java.util.Optional.empty(), java.util.Optional.empty(), java.util.Optional.empty())));
    assertEquals("refresh", label(new RefreshToken("c",
        java.util.Optional.empty(), java.util.Optional.empty(), java.util.Optional.empty())));
    assertEquals("api-key", label(new ApiKey("d",
        java.util.Optional.empty(), java.util.Optional.empty(), java.util.Optional.empty())));
  }
}
