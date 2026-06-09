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
package com.svenruppert.jsentinel.audit;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class PolicyEvaluatedTest {

  private static final Instant TS = Instant.parse("2026-01-01T00:00:00Z");

  @Test
  @DisplayName("constructor rejects null timestamp")
  void rejectsNullTimestamp() {
    assertThrows(NullPointerException.class,
        () -> new PolicyEvaluated(null, "u", "p", "Allowed", "ok"));
  }

  @Test
  @DisplayName("constructor rejects null policyName")
  void rejectsNullPolicyName() {
    assertThrows(NullPointerException.class,
        () -> new PolicyEvaluated(TS, "u", null, "Allowed", "ok"));
  }

  @Test
  @DisplayName("constructor rejects null decision")
  void rejectsNullDecision() {
    assertThrows(NullPointerException.class,
        () -> new PolicyEvaluated(TS, "u", "p", null, "ok"));
  }

  @Test
  @DisplayName("null subjectId is preserved (anonymous is allowed)")
  void anonymousSubjectAllowed() {
    PolicyEvaluated event = new PolicyEvaluated(TS, null, "p", "Denied", "no subject");
    assertEquals(null, event.subjectId());
  }

  @Test
  @DisplayName("null reason is normalised to empty string")
  void nullReasonNormalised() {
    PolicyEvaluated event = new PolicyEvaluated(TS, "u", "p", "Allowed", null);
    assertEquals("", event.reason());
  }

  @Test
  @DisplayName("PolicyEvaluated is an AuditEvent and exposes the configured timestamp")
  void isAuditEvent() {
    AuditEvent event = new PolicyEvaluated(TS, "u", "p", "Allowed", "ok");
    assertSame(TS, event.timestamp());
  }
}
