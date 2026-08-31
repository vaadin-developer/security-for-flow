package eu.jsentinel.jcustos.events.publisher;

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
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.JSentinelEvent;
import eu.jsentinel.jcustos.events.api.JSentinelEventSeverity;
import eu.jsentinel.jcustos.events.bus.JSentinelEventBus;
import eu.jsentinel.jcustos.events.bus.JSentinelEventListener;
import eu.jsentinel.jcustos.events.bus.Registration;
import eu.jsentinel.jcustos.events.types.ListenerFailedEvent;

import java.util.Objects;

/**
 * Turns security events at or above a minimum severity into
 * {@link JSentinelAlert}s and delivers them to a {@link JSentinelAlertSink}.
 *
 * <p><strong>Documented deviation from the envelope tap.</strong> Unlike the
 * in-tree publishers this is a typed {@link JSentinelEventListener}, not a
 * {@link SignedEnvelopePublisher}: alert filtering needs
 * {@link JSentinelEvent#severity()}, and the signed envelope deliberately
 * carries no severity field. Subscribing via {@link #subscribeTo} also means
 * self-observability events (which never produce an envelope) can raise
 * alerts — e.g. a {@code SignatureInvalidEvent} on a critical verification
 * failure reaches the sink.
 *
 * <p>Severity comparison relies on the declaration order of
 * {@link JSentinelEventSeverity} ({@code DEBUG < INFO < NOTICE < WARNING <
 * ERROR < CRITICAL}), so {@code compareTo} expresses "at least as severe".
 * A sink failure is isolated: logged at WARN, never propagated into event
 * dispatch.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class JSentinelAlertPublisher
    implements JSentinelEventListener<JSentinelEvent>, HasLogger {

  /** Default alerting threshold of the single-argument constructor. */
  public static final JSentinelEventSeverity DEFAULT_MINIMUM_SEVERITY =
      JSentinelEventSeverity.ERROR;

  private final JSentinelAlertSink sink;
  private final JSentinelEventSeverity minimumSeverity;

  /**
   * Creates a publisher alerting at {@link #DEFAULT_MINIMUM_SEVERITY} and
   * above.
   *
   * @param sink the alert target
   */
  public JSentinelAlertPublisher(JSentinelAlertSink sink) {
    this(sink, DEFAULT_MINIMUM_SEVERITY);
  }

  /**
   * @param sink the alert target
   * @param minimumSeverity the inclusive severity threshold
   */
  public JSentinelAlertPublisher(JSentinelAlertSink sink,
      JSentinelEventSeverity minimumSeverity) {
    this.sink = Objects.requireNonNull(sink, "sink");
    this.minimumSeverity = Objects.requireNonNull(minimumSeverity, "minimumSeverity");
  }

  @Override
  public void onJSentinelEvent(JSentinelEvent event) {
    if (event == null || event.severity().compareTo(minimumSeverity) < 0) {
      return;
    }
    JSentinelAlert alert = new JSentinelAlert(event.eventType(), event.severity(),
        event.tenantId(), event.subjectId(), event.eventId(), event.occurredAt(),
        detailOf(event));
    try {
      sink.accept(alert);
    } catch (RuntimeException failure) {
      logger().warn("events/alert-sink-failed: sink {} threw on {} ({})",
          sink.getClass().getName(), event.eventType().value(), failure.toString());
    }
  }

  /**
   * Subscribes this publisher to the bus for all events.
   *
   * @param bus the event bus
   * @return the subscription registration
   */
  public Registration subscribeTo(JSentinelEventBus bus) {
    return bus.subscribe(JSentinelEvent.class, this);
  }

  // The detail is a short scrubbed reason, never payload content. For a
  // ListenerFailedEvent the failing listener and its failure code are the
  // reason, so they are included (individually scrubbed — CWE-117).
  private static String detailOf(JSentinelEvent event) {
    if (event instanceof ListenerFailedEvent failed) {
      return failed.getClass().getSimpleName()
          + " listener=" + LogFieldScrubber.scrub(failed.listenerName())
          + " failure=" + LogFieldScrubber.scrub(failed.failureCode());
    }
    return event.getClass().getSimpleName();
  }
}
