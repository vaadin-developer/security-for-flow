package eu.jsentinel.jcustos.events.codec;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.api.PayloadContentType;
import eu.jsentinel.jcustos.events.types.LoginSucceededEvent;
import eu.jsentinel.jcustos.events.types.SequenceViolationEvent;
import eu.jsentinel.jcustos.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("CanonicalJsonPayloadCodec")
class CanonicalJsonPayloadCodecTest {

  private final RecordReflectionCanonicalizer canonicalizer = new RecordReflectionCanonicalizer();
  private final CanonicalJsonPayloadCodec codec = new CanonicalJsonPayloadCodec();

  private static EventMetadata fixedMeta() {
    return new EventMetadata(
        eu.jsentinel.jcustos.events.api.EventId.of("evt-1"),
        TenantId.DEFAULT, SubjectId.of("alice"),
        Instant.parse("2026-06-24T10:15:30Z"), JCustosEventSeverity.INFO);
  }

  @Test
  @DisplayName("contentType is the canonical-json media type")
  void contentType() {
    assertEquals(PayloadContentType.CANONICAL_JSON, codec.contentType());
  }

  @Test
  @DisplayName("encoding is deterministic — identical payload, identical bytes")
  void deterministicBytes() {
    CanonicalJCustosEventPayload payload =
        canonicalizer.canonicalize(new LoginSucceededEvent(fixedMeta(), "password"));
    byte[] first = codec.encode(payload);
    byte[] second = codec.encode(payload);
    assertArrayEquals(first, second);
  }

  @Test
  @DisplayName("encode -> decode round-trips a payload")
  void roundTrip() {
    CanonicalJCustosEventPayload payload =
        canonicalizer.canonicalize(new SequenceViolationEvent(fixedMeta(), "p1", 4, 7));
    CanonicalJCustosEventPayload decoded = codec.decode(codec.encode(payload));
    assertEquals(payload, decoded);
    assertEquals("p1", decoded.attributes().get("producerId"));
    assertEquals("4", decoded.attributes().get("expected"));
    assertEquals("7", decoded.attributes().get("actual"));
    assertEquals("SequenceViolation", decoded.eventType());
  }

  @Test
  @DisplayName("top-level and attribute keys are emitted in sorted order")
  void sortedKeys() {
    CanonicalJCustosEventPayload payload =
        canonicalizer.canonicalize(new SequenceViolationEvent(fixedMeta(), "p1", 4, 7));
    String json = new String(codec.encode(payload), StandardCharsets.UTF_8);
    // top-level: attributes < category < eventId < eventType < occurredAt < schemaVersion ...
    assertTrue(json.indexOf("\"attributes\"") < json.indexOf("\"category\""));
    assertTrue(json.indexOf("\"category\"") < json.indexOf("\"eventId\""));
    assertTrue(json.indexOf("\"schemaVersion\"") < json.indexOf("\"severity\""));
    // no insignificant whitespace
    assertTrue(!json.contains(": "));
    assertTrue(!json.contains(", "));
  }

  @Test
  @DisplayName("special characters in attribute values survive the round trip")
  void escapingRoundTrip() {
    TreeMap<String, String> attrs = new TreeMap<>();
    attrs.put("reason", "line1\nline2\t\"quoted\" \\backslash\\");
    CanonicalJCustosEventPayload payload = new CanonicalJCustosEventPayload(
        CanonicalJCustosEventPayload.SCHEMA_VERSION, "LoginFailed", "e1",
        "default", "alice", "2026-06-24T10:15:30Z", "ERROR", "AUTHENTICATION", attrs);
    CanonicalJCustosEventPayload decoded = codec.decode(codec.encode(payload));
    assertEquals("line1\nline2\t\"quoted\" \\backslash\\", decoded.attributes().get("reason"));
  }

  @Test
  @DisplayName("decoding a non-object or a payload missing a field throws")
  void malformedThrows() {
    assertThrows(PayloadCodecException.class,
        () -> codec.decode("\"not an object\"".getBytes(StandardCharsets.UTF_8)));
    assertThrows(PayloadCodecException.class,
        () -> codec.decode("{\"eventType\":\"X\"}".getBytes(StandardCharsets.UTF_8)));
    assertThrows(PayloadCodecException.class,
        () -> codec.decode("{".getBytes(StandardCharsets.UTF_8)));
  }
}
