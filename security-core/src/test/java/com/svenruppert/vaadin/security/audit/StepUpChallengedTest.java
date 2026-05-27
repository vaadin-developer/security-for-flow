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
package com.svenruppert.vaadin.security.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class StepUpChallengedTest {

  private static final Instant TS = Instant.parse("2026-01-01T00:00:00Z");

  @Test
  @DisplayName("constructor rejects null timestamp")
  void rejectsNullTimestamp() {
    assertThrows(NullPointerException.class,
        () -> new StepUpChallenged(null, "u", "/x", "MFA", "needs mfa"));
  }

  @Test
  @DisplayName("constructor rejects null and blank method")
  void rejectsBlankMethod() {
    assertThrows(IllegalArgumentException.class,
        () -> new StepUpChallenged(TS, "u", "/x", null, "needs mfa"));
    assertThrows(IllegalArgumentException.class,
        () -> new StepUpChallenged(TS, "u", "/x", "", "needs mfa"));
    assertThrows(IllegalArgumentException.class,
        () -> new StepUpChallenged(TS, "u", "/x", "   ", "needs mfa"));
  }

  @Test
  @DisplayName("null subjectId is preserved (anonymous is allowed)")
  void anonymousSubjectAllowed() {
    StepUpChallenged event = new StepUpChallenged(
        TS, null, "/x", "MFA", "needs mfa");
    assertNull(event.subjectId());
  }

  @Test
  @DisplayName("null route is preserved")
  void nullRouteAllowed() {
    StepUpChallenged event = new StepUpChallenged(
        TS, "u", null, "MFA", "needs mfa");
    assertNull(event.route());
  }

  @Test
  @DisplayName("null reason is normalised to empty string")
  void nullReasonNormalised() {
    StepUpChallenged event = new StepUpChallenged(
        TS, "u", "/x", "MFA", null);
    assertEquals("", event.reason());
  }

  @Test
  @DisplayName("StepUpChallenged is an AuditEvent and exposes the configured timestamp")
  void isAuditEvent() {
    AuditEvent event = new StepUpChallenged(TS, "u", "/x", "MFA", "needs mfa");
    assertSame(TS, event.timestamp());
  }

  @Test
  @DisplayName("structured fields survive the record round-trip")
  void fieldsRoundTrip() {
    StepUpChallenged event = new StepUpChallenged(
        TS, "u-alice", "/api/sensitive", "REAUTH", "session too old");
    assertEquals("u-alice", event.subjectId());
    assertEquals("/api/sensitive", event.route());
    assertEquals("REAUTH", event.method());
    assertEquals("session too old", event.reason());
  }
}
