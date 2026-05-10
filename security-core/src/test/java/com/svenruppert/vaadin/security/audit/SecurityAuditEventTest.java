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

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityAuditEventTest {

  @Test
  @DisplayName("constructor rejects null timestamp / type")
  void rejectsNulls() {
    assertThrows(NullPointerException.class,
        () -> new SecurityAuditEvent(null, SecurityAuditEventType.LOGIN_SUCCESS,
            null, null, null, null, null, null, Map.of()));
    assertThrows(NullPointerException.class,
        () -> new SecurityAuditEvent(Instant.now(), null,
            null, null, null, null, null, null, Map.of()));
  }

  @Test
  @DisplayName("constructor accepts a null attributes map and replaces it with an empty one")
  void nullAttributesNormalised() {
    SecurityAuditEvent event = new SecurityAuditEvent(
        Instant.parse("2026-01-01T00:00:00Z"),
        SecurityAuditEventType.LOGOUT,
        "u1", "alice", "/", "DENIED", "127.0.0.1", "sess", null);
    assertNotNull(event.attributes());
    assertTrue(event.attributes().isEmpty());
  }

  @Test
  @DisplayName("attributes are defensively copied (caller mutations do not leak)")
  void attributesAreCopied() {
    Map<String, String> caller = new HashMap<>();
    caller.put("k", "v");
    SecurityAuditEvent event = new SecurityAuditEvent(
        Instant.now(), SecurityAuditEventType.LOGOUT,
        null, null, null, null, null, null, caller);

    caller.put("evil", "x");
    assertEquals(1, event.attributes().size());
    assertEquals("v", event.attributes().get("k"));
  }

  @Test
  @DisplayName("of(type) carries the type and a non-null timestamp")
  void shortcutFactory() {
    SecurityAuditEvent e = SecurityAuditEvent.of(SecurityAuditEventType.ACCESS_GRANTED);
    assertSame(SecurityAuditEventType.ACCESS_GRANTED, e.type());
    assertNotNull(e.timestamp());
    assertNull(e.subjectId());
    assertTrue(e.attributes().isEmpty());
  }

  @Test
  @DisplayName("Builder applies a custom Clock")
  void builderUsesClock() {
    Clock fixed = Clock.fixed(Instant.parse("2026-05-08T10:00:00Z"), ZoneOffset.UTC);
    SecurityAuditEvent e = SecurityAuditEvent.builder(SecurityAuditEventType.LOGIN_SUCCESS)
        .clock(fixed)
        .subjectId("s")
        .username("alice")
        .route("/login")
        .decision("ACCEPTED")
        .clientAddress("10.0.0.1")
        .sessionId("S")
        .attribute("k", "v")
        .build();

    assertEquals(Instant.parse("2026-05-08T10:00:00Z"), e.timestamp());
    assertEquals("s", e.subjectId());
    assertEquals("alice", e.username());
    assertEquals("/login", e.route());
    assertEquals("ACCEPTED", e.decision());
    assertEquals("10.0.0.1", e.clientAddress());
    assertEquals("S", e.sessionId());
    assertEquals("v", e.attributes().get("k"));
  }

  @Test
  @DisplayName("Builder.attribute(_, null) is a no-op")
  void builderIgnoresNullAttributeValues() {
    SecurityAuditEvent e = SecurityAuditEvent.builder(SecurityAuditEventType.LOGOUT)
        .attribute("present", "v")
        .attribute("absent", null)
        .build();

    assertEquals(1, e.attributes().size());
    assertEquals("v", e.attributes().get("present"));
  }

  @Test
  @DisplayName("Builder.attributes(map) merges all entries")
  void builderMergesMap() {
    SecurityAuditEvent e = SecurityAuditEvent.builder(SecurityAuditEventType.ACCESS_DENIED)
        .attributes(Map.of("a", "1", "b", "2"))
        .build();

    assertEquals(2, e.attributes().size());
    assertEquals("1", e.attributes().get("a"));
    assertEquals("2", e.attributes().get("b"));
  }
}
