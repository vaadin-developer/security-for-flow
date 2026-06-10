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
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("HeaderValue — RFC 7230 §3.2.6 validation")
class HeaderValueValidationTest {

  @Test
  @DisplayName("Empty name is rejected")
  void emptyNameRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> new HeaderValue("", "v"));
  }

  @Test
  @DisplayName("Name with CR / LF / control rejected")
  void invalidNameRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> new HeaderValue("X\r", "v"));
    assertThrows(IllegalArgumentException.class,
        () -> new HeaderValue("X\n", "v"));
    assertThrows(IllegalArgumentException.class,
        () -> new HeaderValue("X", "v"));
  }

  @Test
  @DisplayName("Name containing a space is rejected")
  void spaceInNameRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> new HeaderValue("X Custom", "v"));
  }

  @Test
  @DisplayName("Canonical header names accepted")
  void canonicalNamesAccepted() {
    new HeaderValue("Authorization", "Bearer abc");
    new HeaderValue("X-Custom-Token", "anything");
    new HeaderValue("X-Api-Key", "xyz");
  }

  @Test
  @DisplayName("Value rejecting CR / LF / control bytes")
  void invalidValueRejected() {
    assertThrows(IllegalArgumentException.class,
        () -> new HeaderValue("X", "a\rb"));
    assertThrows(IllegalArgumentException.class,
        () -> new HeaderValue("X", "a\nb"));
    assertThrows(IllegalArgumentException.class,
        () -> new HeaderValue("X", "ab"));
  }

  @Test
  @DisplayName("Value accepts tab + obs-text high bytes")
  void valueAcceptsObsText() {
    new HeaderValue("X", "a\tb");
    new HeaderValue("X", "value-with-ÿ-high-byte");
  }

  @Test
  @DisplayName("Accessors return the same data")
  void accessors() {
    HeaderValue h = new HeaderValue("Authorization", "Bearer abc");
    assertEquals("Authorization", h.name());
    assertEquals("Bearer abc", h.value());
  }
}
