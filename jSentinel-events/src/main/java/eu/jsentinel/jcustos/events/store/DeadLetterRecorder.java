package eu.jsentinel.jcustos.events.store;

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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.EventMetadata;
import eu.jsentinel.jcustos.events.api.JSentinelEvent;
import eu.jsentinel.jcustos.events.api.JSentinelEventSeverity;
import eu.jsentinel.jcustos.events.api.SignedJSentinelEventEnvelope;
import eu.jsentinel.jcustos.events.bus.EventBusObservabilityPublisher;
import eu.jsentinel.jcustos.events.types.DeadLetteredEvent;

import java.time.Instant;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * The canonical dead-letter emission point: stores a rejected envelope as a
 * {@link JSentinelEventDeadLetter} and emits the matching
 * {@link DeadLetteredEvent} through the observability publisher.
 *
 * <p>Store and emission are strictly ordered: the store write comes first and
 * a store failure <em>propagates</em> — losing a dead letter must be visible
 * to the caller. The subsequent event emission is best-effort: an emission
 * failure is logged ({@code events/deadletter-event-failed}) and never masks
 * a successful store.
 *
 * <p>Routing policy — <em>which</em> rejections are dead-lettered at all — is
 * deliberately out of scope here; callers decide what to route into
 * {@link #record(SignedJSentinelEventEnvelope, RejectionReason)}.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class DeadLetterRecorder implements HasLogger {

  private final JSentinelEventDeadLetterStore store;
  private final EventBusObservabilityPublisher observability;
  private final Supplier<Instant> clock;

  public DeadLetterRecorder(JSentinelEventDeadLetterStore store,
      EventBusObservabilityPublisher observability, Supplier<Instant> clock) {
    this.store = Objects.requireNonNull(store, "store");
    this.observability = Objects.requireNonNull(observability, "observability");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  /**
   * Records a rejected envelope: builds the dead letter, stores it, then
   * emits a {@link DeadLetteredEvent} (reason string is
   * {@link RejectionReason#name()}).
   *
   * @param envelope the rejected envelope
   * @param reason why it was rejected
   * @return the stored dead-letter record
   * @throws RuntimeException whatever the store throws — a failed store write
   *     is never swallowed
   */
  public JSentinelEventDeadLetter record(SignedJSentinelEventEnvelope envelope,
      RejectionReason reason) {
    Objects.requireNonNull(envelope, "envelope");
    Objects.requireNonNull(reason, "reason");
    Instant now = clock.get();
    JSentinelEventDeadLetter deadLetter = JSentinelEventDeadLetter.of(envelope, reason, now);
    store.store(deadLetter);
    try {
      EventMetadata metadata = EventMetadata.create(envelope.tenantId(),
          JSentinelEvent.SYSTEM_SUBJECT, now, JSentinelEventSeverity.ERROR);
      observability.publishObservability(new DeadLetteredEvent(metadata,
          envelope.envelopeId().value(), reason.name()));
    } catch (RuntimeException failure) {
      logger().warn("events/deadletter-event-failed: DeadLettered emission failed for {} ({})",
          envelope.envelopeId().value(), failure.toString());
    }
    return deadLetter;
  }
}
