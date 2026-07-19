package com.svenruppert.jsentinel.events.rest;

/*-
 * #%L
 * jSentinel Events — REST / SSE bridge
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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * The deprecated V00.75 {@code events.rest.EnvelopeWireCodec} shim must keep
 * encoding and decoding exactly like the moved
 * {@code events.wire.EnvelopeWireCodec} until its removal.
 */
@SuppressWarnings("removal")
@DisplayName("EnvelopeWireCodec — deprecated events-rest delegator")
class EnvelopeWireCodecDelegatorTest {

  private final EnvelopeWireCodec deprecated = new EnvelopeWireCodec();
  private final com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec moved =
      new com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec();

  @Test
  @DisplayName("encode is byte-identical to the moved codec")
  void encodeIsIdentical() {
    SignedJSentinelEventEnvelope env = new EventsRestFixtures().signedEnvelope();
    assertEquals(moved.encode(env), deprecated.encode(env));
  }

  @Test
  @DisplayName("decode round-trips an envelope encoded by the moved codec")
  void decodeRoundTrips() {
    SignedJSentinelEventEnvelope env = new EventsRestFixtures().signedEnvelope();
    assertEquals(env, deprecated.decode(moved.encode(env)).getOrThrow());
  }

  @Test
  @DisplayName("malformed input still lands in the error channel")
  void malformedIsFailure() {
    assertTrue(deprecated.decode("{").isFailure());
  }
}
