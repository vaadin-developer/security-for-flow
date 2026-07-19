package com.svenruppert.jsentinel.events.wire;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
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

import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("EnvelopeWireCodec")
class EnvelopeWireCodecTest {

  private final EnvelopeWireCodec codec = new EnvelopeWireCodec();

  @Test
  @DisplayName("encode -> decode round-trips a signed envelope by value")
  void roundTrip() {
    SignedJSentinelEventEnvelope env = new WireFixtures().signedEnvelope();
    String json = codec.encode(env);
    SignedJSentinelEventEnvelope decoded = codec.decode(json).getOrThrow();
    assertEquals(env, decoded);
  }

  @Test
  @DisplayName("the wire form is a JSON object carrying the envelope id and a numeric sequence")
  void wireShape() {
    SignedJSentinelEventEnvelope env = new WireFixtures().signedEnvelope();
    String json = codec.encode(env);
    assertTrue(json.startsWith("{") && json.endsWith("}"));
    assertTrue(json.contains("\"envelopeId\":\"" + env.envelopeId().value() + "\""));
    assertTrue(json.contains("\"sequence\":" + env.sequence().value()));
  }

  @Test
  @DisplayName("decoding malformed JSON or a missing field is a Failure, not a thrown exception")
  void malformed() {
    assertTrue(codec.decode("{").isFailure());
    assertTrue(codec.decode("{\"envelopeId\":\"x\"}").isFailure());
  }

  @Test
  @DisplayName("JS-SEC-019: a malformed body's decode error carries no control chars (no log-forging)")
  void decodeErrorHasNoControlChars() {
    // Malformed inputs whose parse error may echo attacker-controlled fragments,
    // including raw CR/LF that could forge extra log lines when the error is logged.
    for (String bad : List.of(
        "{\"eventType\":\"a\r\nFAKE 200 OK\"}",
        "{\"createdAt\":\"2026\n01\n01\"}",
        "not json\r\ninjected line",
        "{")) {
      String error = codec.decode(bad).fold(v -> "", e -> e);
      for (int i = 0; i < error.length(); i++) {
        assertFalse(Character.isISOControl(error.charAt(i)),
            "decode error must be free of control chars (JS-SEC-019); got: " + error);
      }
    }
  }

  @Test
  @DisplayName("encodeMetadata omits canonicalPayload and signature but keeps the payload hash")
  void metadataOmitsPayloadAndSignature() {
    SignedJSentinelEventEnvelope env = new WireFixtures().signedEnvelope();
    String json = codec.encodeMetadata(env);
    assertFalse(json.contains("\"canonicalPayload\":"),
        "metadata projection must not carry the payload field");
    assertFalse(json.contains("\"signature\":"),
        "metadata projection must not carry the signature field");
    assertFalse(json.contains(Base64.getEncoder().encodeToString(env.canonicalPayload())),
        "metadata projection must not carry the Base64 payload bytes");
    assertTrue(json.contains("\"canonicalPayloadHash\":\"" + env.canonicalPayloadHash() + "\""),
        "metadata projection keeps the payload hash");
  }

  @Test
  @DisplayName("encodeMetadata carries the same metadata field values as encode")
  void metadataMatchesFullForm() {
    SignedJSentinelEventEnvelope env = new WireFixtures().signedEnvelope();
    String metadata = codec.encodeMetadata(env);
    assertTrue(metadata.startsWith("{") && metadata.endsWith("}"));
    assertTrue(metadata.contains("\"envelopeId\":\"" + env.envelopeId().value() + "\""));
    assertTrue(metadata.contains("\"eventType\":\"" + env.eventType().value() + "\""));
    assertTrue(metadata.contains("\"sequence\":" + env.sequence().value()));
    assertTrue(metadata.contains("\"signatureAlgorithm\":\""
        + env.signatureAlgorithm().value() + "\""));
    // the full wire form starts with exactly this projection (field order is stable)
    String full = codec.encode(env);
    assertTrue(full.startsWith(
        metadata.substring(0, metadata.length() - 1) + ",\"canonicalPayload\":"));
  }

  @Test
  @DisplayName("the metadata projection is one-way: it does not decode back into an envelope")
  void metadataIsNotDecodable() {
    SignedJSentinelEventEnvelope env = new WireFixtures().signedEnvelope();
    assertTrue(codec.decode(codec.encodeMetadata(env)).isFailure());
  }
}
