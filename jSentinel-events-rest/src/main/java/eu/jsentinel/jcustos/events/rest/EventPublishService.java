package eu.jsentinel.jcustos.events.rest;

/*-
 * #%L
 * jCustos Events — REST / SSE bridge
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.bus.ConsumeFailureHandler;
import eu.jsentinel.jcustos.events.bus.ConsumePipeline;
import eu.jsentinel.jcustos.events.bus.JCustosEventVerificationResult;
import eu.jsentinel.jcustos.events.store.JCustosEventCursor;
import eu.jsentinel.jcustos.events.store.JCustosEventEnvelopeStore;
import eu.jsentinel.jcustos.events.store.StoredEnvelope;
import eu.jsentinel.jcustos.events.wire.EnvelopeWireCodec;

import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * Framework-light publish handler for the bridge (Konzept §970): decode a wire
 * envelope, run the full {@link ConsumePipeline}, and on success store + live-
 * broadcast it. Maps every {@link JCustosEventVerificationResult} to an
 * {@link EventPublishOutcome}. HTTP-server-agnostic, so it can be unit-tested
 * directly and reused behind any transport.
 *
 * @since 00.75.00
 */
@ExperimentalJCustosApi
public final class EventPublishService implements HasLogger {

  private final EnvelopeWireCodec wireCodec;
  private final ConsumePipeline consumePipeline;
  private final JCustosEventEnvelopeStore envelopeStore;
  private final SseEventBroadcaster broadcaster;
  private final Supplier<Instant> clock;
  private final ConsumeFailureHandler failureHandler;

  public EventPublishService(EnvelopeWireCodec wireCodec, ConsumePipeline consumePipeline,
      JCustosEventEnvelopeStore envelopeStore, SseEventBroadcaster broadcaster,
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
      JCustosEventEnvelopeStore envelopeStore, SseEventBroadcaster broadcaster,
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

  private EventPublishOutcome verifyAndMap(SignedJCustosEventEnvelope envelope) {
    JCustosEventVerificationResult result = consumePipeline.verify(envelope, clock.get());
    if (failureHandler != null
        && !(result instanceof JCustosEventVerificationResult.Valid)) {
      // P012: event + metric seam + optional dead letter — the handler is
      // total and never changes the HTTP outcome below.
      failureHandler.handle(envelope, result);
    }
    return switch (result) {
      case JCustosEventVerificationResult.Valid v -> accept(v.envelope());
      case JCustosEventVerificationResult.InvalidSignature ignored ->
          new EventPublishOutcome(HttpStatus.BAD_REQUEST.code(),
              EventPublishBodies.INVALID_SIGNATURE);
      case JCustosEventVerificationResult.PayloadHashMismatch ignored ->
          new EventPublishOutcome(HttpStatus.BAD_REQUEST.code(),
              EventPublishBodies.PAYLOAD_HASH_MISMATCH);
      case JCustosEventVerificationResult.UnknownKey ignored ->
          new EventPublishOutcome(HttpStatus.BAD_REQUEST.code(),
              EventPublishBodies.UNKNOWN_KEY);
      case JCustosEventVerificationResult.KeyRevoked ignored ->
          new EventPublishOutcome(HttpStatus.FORBIDDEN.code(),
              EventPublishBodies.KEY_REVOKED);
      case JCustosEventVerificationResult.KeyExpired ignored ->
          new EventPublishOutcome(HttpStatus.FORBIDDEN.code(),
              EventPublishBodies.KEY_EXPIRED);
      case JCustosEventVerificationResult.Expired ignored ->
          new EventPublishOutcome(HttpStatus.GONE.code(),
              EventPublishBodies.EXPIRED);
      case JCustosEventVerificationResult.ReplayDetected ignored ->
          new EventPublishOutcome(HttpStatus.CONFLICT.code(),
              EventPublishBodies.REPLAY_DETECTED);
      case JCustosEventVerificationResult.SequenceViolation ignored ->
          new EventPublishOutcome(HttpStatus.CONFLICT.code(),
              EventPublishBodies.SEQUENCE_VIOLATION);
      case JCustosEventVerificationResult.ProducerNotAllowed ignored ->
          new EventPublishOutcome(HttpStatus.FORBIDDEN.code(),
              EventPublishBodies.PRODUCER_NOT_ALLOWED);
    };
  }

  private EventPublishOutcome accept(SignedJCustosEventEnvelope envelope) {
    if (envelopeStore != null) {
      JCustosEventCursor cursor = envelopeStore.append(envelope);
      if (broadcaster != null) {
        broadcaster.broadcast(new StoredEnvelope(cursor, envelope));
      }
    }
    return new EventPublishOutcome(HttpStatus.ACCEPTED.code(), EventPublishBodies.ACCEPTED);
  }
}
