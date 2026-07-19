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
import com.svenruppert.jsentinel.events.bus.ConsumeFailureHandler;
import com.svenruppert.jsentinel.events.bus.ConsumePipeline;
import com.svenruppert.jsentinel.events.bus.JSentinelEventVerificationResult;
import com.svenruppert.jsentinel.events.store.JSentinelEventCursor;
import com.svenruppert.jsentinel.events.store.JSentinelEventEnvelopeStore;
import com.svenruppert.jsentinel.events.store.StoredEnvelope;
import com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec;

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
  private final ConsumeFailureHandler failureHandler;

  public EventPublishService(EnvelopeWireCodec wireCodec, ConsumePipeline consumePipeline,
      JSentinelEventEnvelopeStore envelopeStore, SseEventBroadcaster broadcaster,
      Supplier<Instant> clock) {
    this(wireCodec, consumePipeline, envelopeStore, broadcaster, clock, null);
  }

  /**
   * V00.80.00 (P012): variant with the strict-mode failure wiring — every
   * verification failure additionally flows through the
   * {@link ConsumeFailureHandler} (self-observability event, optional dead
   * letter, operator log). The HTTP outcome mapping is byte-identical with
   * and without a handler.
   *
   * @param failureHandler the failure wiring; {@code null} skips it
   * @since 00.80.00
   */
  public EventPublishService(EnvelopeWireCodec wireCodec, ConsumePipeline consumePipeline,
      JSentinelEventEnvelopeStore envelopeStore, SseEventBroadcaster broadcaster,
      Supplier<Instant> clock, ConsumeFailureHandler failureHandler) {
    this.wireCodec = Objects.requireNonNull(wireCodec, "wireCodec");
    this.consumePipeline = Objects.requireNonNull(consumePipeline, "consumePipeline");
    this.envelopeStore = envelopeStore; // optional
    this.broadcaster = broadcaster; // optional
    this.clock = Objects.requireNonNull(clock, "clock");
    this.failureHandler = failureHandler; // optional
  }

  /**
   * Processes a publish request body.
   *
   * @param body the JSON envelope
   * @return the outcome to render
   */
  public EventPublishOutcome publish(String body) {
    return wireCodec.decode(body).fold(
        this::verifyAndMap,
        error -> {
          logger().warn("events-rest/publish-malformed: {}", error);
          return new EventPublishOutcome(HttpStatus.BAD_REQUEST.code(),
              EventPublishBodies.MALFORMED_ENVELOPE);
        });
  }

  private EventPublishOutcome verifyAndMap(SignedJSentinelEventEnvelope envelope) {
    JSentinelEventVerificationResult result = consumePipeline.verify(envelope, clock.get());
    if (failureHandler != null
        && !(result instanceof JSentinelEventVerificationResult.Valid)) {
      // P012: event + metric seam + optional dead letter — the handler is
      // total and never changes the HTTP outcome below.
      failureHandler.handle(envelope, result);
    }
    return switch (result) {
      case JSentinelEventVerificationResult.Valid v -> accept(v.envelope());
      case JSentinelEventVerificationResult.InvalidSignature ignored ->
          new EventPublishOutcome(HttpStatus.BAD_REQUEST.code(),
              EventPublishBodies.INVALID_SIGNATURE);
      case JSentinelEventVerificationResult.PayloadHashMismatch ignored ->
          new EventPublishOutcome(HttpStatus.BAD_REQUEST.code(),
              EventPublishBodies.PAYLOAD_HASH_MISMATCH);
      case JSentinelEventVerificationResult.UnknownKey ignored ->
          new EventPublishOutcome(HttpStatus.BAD_REQUEST.code(),
              EventPublishBodies.UNKNOWN_KEY);
      case JSentinelEventVerificationResult.KeyRevoked ignored ->
          new EventPublishOutcome(HttpStatus.FORBIDDEN.code(),
              EventPublishBodies.KEY_REVOKED);
      case JSentinelEventVerificationResult.KeyExpired ignored ->
          new EventPublishOutcome(HttpStatus.FORBIDDEN.code(),
              EventPublishBodies.KEY_EXPIRED);
      case JSentinelEventVerificationResult.Expired ignored ->
          new EventPublishOutcome(HttpStatus.GONE.code(),
              EventPublishBodies.EXPIRED);
      case JSentinelEventVerificationResult.ReplayDetected ignored ->
          new EventPublishOutcome(HttpStatus.CONFLICT.code(),
              EventPublishBodies.REPLAY_DETECTED);
      case JSentinelEventVerificationResult.SequenceViolation ignored ->
          new EventPublishOutcome(HttpStatus.CONFLICT.code(),
              EventPublishBodies.SEQUENCE_VIOLATION);
      case JSentinelEventVerificationResult.ProducerNotAllowed ignored ->
          new EventPublishOutcome(HttpStatus.FORBIDDEN.code(),
              EventPublishBodies.PRODUCER_NOT_ALLOWED);
    };
  }

  private EventPublishOutcome accept(SignedJSentinelEventEnvelope envelope) {
    if (envelopeStore != null) {
      JSentinelEventCursor cursor = envelopeStore.append(envelope);
      if (broadcaster != null) {
        broadcaster.broadcast(new StoredEnvelope(cursor, envelope));
      }
    }
    return new EventPublishOutcome(HttpStatus.ACCEPTED.code(), EventPublishBodies.ACCEPTED);
  }
}
