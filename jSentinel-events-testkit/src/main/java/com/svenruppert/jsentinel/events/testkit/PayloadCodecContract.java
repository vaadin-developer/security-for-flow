package com.svenruppert.jsentinel.events.testkit;

/*-
 * #%L
 * jSentinel Events — Contract testkit
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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.codec.CanonicalJSentinelEventPayload;
import com.svenruppert.jsentinel.events.codec.PayloadCodec;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.TreeMap;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Reusable contract for {@link PayloadCodec} implementations: a codec must
 * produce deterministic bytes (the signature binds to them) and round-trip a
 * payload (Konzept §427-§429).
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
@DisplayName("PayloadCodec — contract")
public interface PayloadCodecContract {

  PayloadCodec newCodec();

  private static CanonicalJSentinelEventPayload samplePayload() {
    TreeMap<String, String> attributes = new TreeMap<>();
    attributes.put("authenticationMethod", "password");
    attributes.put("note", "line1\nline2\t\"q\"");
    return new CanonicalJSentinelEventPayload(
        CanonicalJSentinelEventPayload.SCHEMA_VERSION, "LoginSucceeded", "evt-1",
        "default", "alice", "2026-06-24T10:15:30Z", "INFO", "AUTHENTICATION", attributes);
  }

  @Test
  @DisplayName("contentType is non-null")
  default void contentTypeNonNull() {
    assertNotNull(newCodec().contentType());
  }

  @Test
  @DisplayName("encoding the same payload twice yields identical bytes")
  default void deterministic() {
    PayloadCodec codec = newCodec();
    CanonicalJSentinelEventPayload payload = samplePayload();
    assertArrayEquals(codec.encode(payload), codec.encode(payload));
  }

  @Test
  @DisplayName("encode -> decode round-trips the payload")
  default void roundTrip() {
    PayloadCodec codec = newCodec();
    CanonicalJSentinelEventPayload payload = samplePayload();
    assertEquals(payload, codec.decode(codec.encode(payload)));
  }
}
