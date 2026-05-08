/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.vaadin.security.bootstrap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BootstrapTokenTest {

  private static final Instant ANCHOR = Instant.parse("2026-01-01T00:00:00Z");

  @Test
  @DisplayName("constructor rejects null value")
  void rejectsNullValue() {
    assertThrows(NullPointerException.class,
        () -> new BootstrapToken(null, ANCHOR));
  }

  @Test
  @DisplayName("constructor rejects blank value")
  void rejectsBlankValue() {
    assertThrows(IllegalArgumentException.class,
        () -> new BootstrapToken("   ", ANCHOR));
  }

  @Test
  @DisplayName("constructor rejects null createdAt")
  void rejectsNullCreatedAt() {
    assertThrows(NullPointerException.class,
        () -> new BootstrapToken("ABCD", null));
  }

  @Test
  @DisplayName("matches returns true for the exact same string")
  void matchesAcceptsEqual() {
    BootstrapToken t = new BootstrapToken("AAAA-BBBB-CCCC-DDDD-EEEE", ANCHOR);
    assertTrue(t.matches("AAAA-BBBB-CCCC-DDDD-EEEE"));
  }

  @Test
  @DisplayName("matches returns false for a different string")
  void matchesRejectsDifferent() {
    BootstrapToken t = new BootstrapToken("AAAA-BBBB-CCCC-DDDD-EEEE", ANCHOR);
    assertFalse(t.matches("AAAA-BBBB-CCCC-DDDD-EEEF"));
  }

  @Test
  @DisplayName("matches returns false for null candidate")
  void matchesRejectsNull() {
    BootstrapToken t = new BootstrapToken("X", ANCHOR);
    assertFalse(t.matches(null));
  }

  @Test
  @DisplayName("matches returns false when candidate is a prefix")
  void matchesRejectsPrefix() {
    BootstrapToken t = new BootstrapToken("ABCD", ANCHOR);
    assertFalse(t.matches("ABC"));
  }

  @Test
  @DisplayName("matches returns false when candidate is longer")
  void matchesRejectsSuffixed() {
    BootstrapToken t = new BootstrapToken("ABCD", ANCHOR);
    assertFalse(t.matches("ABCDE"));
  }

  @Test
  @DisplayName("isExpired is false strictly within validity window")
  void isExpiredFalseWithinWindow() {
    BootstrapToken t = new BootstrapToken("X", ANCHOR);
    assertFalse(t.isExpired(ANCHOR.plus(Duration.ofHours(1)), Duration.ofHours(2)));
  }

  @Test
  @DisplayName("isExpired is false at the exact deadline (boundary)")
  void isExpiredFalseAtBoundary() {
    BootstrapToken t = new BootstrapToken("X", ANCHOR);
    assertFalse(t.isExpired(ANCHOR.plus(Duration.ofHours(2)), Duration.ofHours(2)));
  }

  @Test
  @DisplayName("isExpired is true after the deadline")
  void isExpiredTrueAfterWindow() {
    BootstrapToken t = new BootstrapToken("X", ANCHOR);
    assertTrue(t.isExpired(ANCHOR.plus(Duration.ofHours(3)), Duration.ofHours(2)));
  }

  @Test
  @DisplayName("isExpired rejects null arguments")
  void isExpiredRejectsNullArgs() {
    BootstrapToken t = new BootstrapToken("X", ANCHOR);
    assertThrows(NullPointerException.class,
        () -> t.isExpired(null, Duration.ofHours(2)));
    assertThrows(NullPointerException.class,
        () -> t.isExpired(ANCHOR, null));
  }
}
