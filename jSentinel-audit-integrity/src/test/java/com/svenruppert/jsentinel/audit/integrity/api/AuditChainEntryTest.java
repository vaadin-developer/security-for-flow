package com.svenruppert.jsentinel.audit.integrity.api;

/*-
 * #%L
 * jSentinel Audit Integrity — tamper-evident audit
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import com.svenruppert.jsentinel.events.api.PayloadHashAlgorithm;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

@DisplayName("AuditChainEntry — validation, defensive bytes, value semantics")
class AuditChainEntryTest {

  private static final Instant AT = Instant.parse("2026-07-19T10:15:30Z");

  private static AuditChainEntry entry(byte[] payload) {
    return new AuditChainEntry(0, AT, PayloadHashAlgorithm.SHA_256,
        AuditChainEntry.GENESIS_PREVIOUS_HASH, "aa11", "test/v1", payload);
  }

  @Test
  @DisplayName("guards: negative index and blank strings are rejected")
  void guards() {
    byte[] payload = "p".getBytes(StandardCharsets.UTF_8);
    assertThrows(IllegalArgumentException.class, () ->
        new AuditChainEntry(-1, AT, PayloadHashAlgorithm.SHA_256,
            "prev", "hash", "type", payload));
    assertThrows(IllegalArgumentException.class, () ->
        new AuditChainEntry(0, AT, PayloadHashAlgorithm.SHA_256,
            " ", "hash", "type", payload));
    assertThrows(IllegalArgumentException.class, () ->
        new AuditChainEntry(0, AT, PayloadHashAlgorithm.SHA_256,
            "prev", "", "type", payload));
    assertThrows(IllegalArgumentException.class, () ->
        new AuditChainEntry(0, AT, PayloadHashAlgorithm.SHA_256,
            "prev", "hash", " ", payload));
    assertThrows(NullPointerException.class, () ->
        new AuditChainEntry(0, AT, PayloadHashAlgorithm.SHA_256,
            "prev", "hash", "type", null));
  }

  @Test
  @DisplayName("payload bytes are defensively copied on the way in and out")
  void defensivePayload() {
    byte[] input = "payload".getBytes(StandardCharsets.UTF_8);
    AuditChainEntry entry = entry(input);
    input[0] = 'X';
    assertEquals('p', entry.payload()[0], "construction must have copied");

    entry.payload()[0] = 'Y';
    assertEquals('p', entry.payload()[0], "the accessor must return a copy");
  }

  @Test
  @DisplayName("value semantics include the payload bytes")
  void valueSemantics() {
    AuditChainEntry first = entry("same".getBytes(StandardCharsets.UTF_8));
    AuditChainEntry second = entry("same".getBytes(StandardCharsets.UTF_8));
    AuditChainEntry different = entry("diff".getBytes(StandardCharsets.UTF_8));

    assertEquals(first, second);
    assertEquals(first.hashCode(), second.hashCode());
    assertNotEquals(first, different);
  }

  @Test
  @DisplayName("toString never dumps payload bytes")
  void toStringHasNoPayload() {
    AuditChainEntry entry = entry("top-secret-subject-data".getBytes(StandardCharsets.UTF_8));
    assertFalse(entry.toString().contains("top-secret-subject-data"));
  }
}
