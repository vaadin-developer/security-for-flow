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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.dependencies.core.net.HttpStatus;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import com.svenruppert.jsentinel.events.bus.ConsumePipeline;
import com.svenruppert.jsentinel.events.bus.JSentinelEventVerificationResult;
import com.svenruppert.jsentinel.events.store.JSentinelEventCursor;
import com.svenruppert.jsentinel.events.store.JSentinelEventEnvelopeStore;
import com.svenruppert.jsentinel.events.store.StoredEnvelope;

import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Framework-light publish handler for the bridge (Konzept §970): decode a wire
 * envelope, run the full {@link ConsumePipeline}, and on success store + live-
 * broadcast it. Maps every {@link JSentinelEventVerificationResult} to an
 * {@link EventPublishOutcome}. HTTP-server-agnostic, so it can be unit-tested
 * directly and reused behind any transport.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class EventPublishService implements HasLogger {

  private final EnvelopeWireCodec wireCodec;
  private final ConsumePipeline consumePipeline;
  private final JSentinelEventEnvelopeStore envelopeStore;
  private final SseEventBroadcaster broadcaster;
  private final Supplier<Instant> clock;

  public EventPublishService(EnvelopeWireCodec wireCodec, ConsumePipeline consumePipeline,
      JSentinelEventEnvelopeStore envelopeStore, SseEventBroadcaster broadcaster,
      Supplier<Instant> clock) {
    this.wireCodec = Objects.requireNonNull(wireCodec, "wireCodec");
    this.consumePipeline = Objects.requireNonNull(consumePipeline, "consumePipeline");
    this.envelopeStore = envelopeStore; // optional
    this.broadcaster = broadcaster; // optional
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Processes a publish request body.
   *
   * @param body the JSON envelope
   * @return the outcome to render
   */
  public EventPublishOutcome publish(String body) {
    SignedJSentinelEventEnvelope envelope;
    try {
      envelope = wireCodec.decode(body);
    } catch (RuntimeException malformed) {
      logger().warn("events-rest/publish-malformed: {}", malformed.toString());
      return new EventPublishOutcome(HttpStatus.BAD_REQUEST.code(), "Malformed envelope");
    }

    JSentinelEventVerificationResult result = consumePipeline.verify(envelope, clock.get());
    return switch (result) {
      case JSentinelEventVerificationResult.Valid v -> accept(v.envelope());
      case JSentinelEventVerificationResult.InvalidSignature ignored ->
          new EventPublishOutcome(HttpStatus.BAD_REQUEST.code(), "Invalid signature");
      case JSentinelEventVerificationResult.PayloadHashMismatch ignored ->
          new EventPublishOutcome(HttpStatus.BAD_REQUEST.code(), "Payload hash mismatch");
      case JSentinelEventVerificationResult.UnknownKey ignored ->
          new EventPublishOutcome(HttpStatus.BAD_REQUEST.code(), "Unknown key");
      case JSentinelEventVerificationResult.KeyRevoked ignored ->
          new EventPublishOutcome(HttpStatus.FORBIDDEN.code(), "Key revoked");
      case JSentinelEventVerificationResult.Expired ignored ->
          new EventPublishOutcome(HttpStatus.GONE.code(), "Expired");
      case JSentinelEventVerificationResult.ReplayDetected ignored ->
          new EventPublishOutcome(HttpStatus.CONFLICT.code(), "Replay detected");
      case JSentinelEventVerificationResult.SequenceViolation ignored ->
          new EventPublishOutcome(HttpStatus.CONFLICT.code(), "Sequence violation");
      case JSentinelEventVerificationResult.ProducerNotAllowed ignored ->
          new EventPublishOutcome(HttpStatus.FORBIDDEN.code(), "Producer not allowed");
    };
  }

  private EventPublishOutcome accept(SignedJSentinelEventEnvelope envelope) {
    if (envelopeStore != null) {
      JSentinelEventCursor cursor = envelopeStore.append(envelope);
      if (broadcaster != null) {
        broadcaster.broadcast(new StoredEnvelope(cursor, envelope));
      }
    }
    return new EventPublishOutcome(HttpStatus.ACCEPTED.code(), "Accepted");
  }
}
