package eu.jsentinel.jcustos.events.publisher;

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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.JCustosEvent;
import eu.jsentinel.jcustos.events.api.JCustosEventSeverity;
import eu.jsentinel.jcustos.events.bus.JCustosEventBus;
import eu.jsentinel.jcustos.events.bus.JCustosEventListener;
import eu.jsentinel.jcustos.events.bus.Registration;
import eu.jsentinel.jcustos.events.types.ListenerFailedEvent;

import java.util.Objects;

/**
 * Turns security events at or above a minimum severity into
 * {@link JCustosAlert}s and delivers them to a {@link JCustosAlertSink}.
 *
 * <p><strong>Documented deviation from the envelope tap.</strong> Unlike the
 * in-tree publishers this is a typed {@link JCustosEventListener}, not a
 * {@link SignedEnvelopePublisher}: alert filtering needs
 * {@link JCustosEvent#severity()}, and the signed envelope deliberately
 * carries no severity field. Subscribing via {@link #subscribeTo} also means
 * self-observability events (which never produce an envelope) can raise
 * alerts — e.g. a {@code SignatureInvalidEvent} on a critical verification
 * failure reaches the sink.
 *
 * <p>Severity comparison relies on the declaration order of
 * {@link JCustosEventSeverity} ({@code DEBUG < INFO < NOTICE < WARNING <
 * ERROR < CRITICAL}), so {@code compareTo} expresses "at least as severe".
 * A sink failure is isolated: logged at WARN, never propagated into event
 * dispatch.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class JCustosAlertPublisher
    implements JCustosEventListener<JCustosEvent>, HasLogger {

  /** Default alerting threshold of the single-argument constructor. */
  public static final JCustosEventSeverity DEFAULT_MINIMUM_SEVERITY =
      JCustosEventSeverity.ERROR;

  private final JCustosAlertSink sink;
  private final JCustosEventSeverity minimumSeverity;

  /**
   * Creates a publisher alerting at {@link #DEFAULT_MINIMUM_SEVERITY} and
   * above.
   *
   * @param sink the alert target
   */
  public JCustosAlertPublisher(JCustosAlertSink sink) {
    this(sink, DEFAULT_MINIMUM_SEVERITY);
  }

  /**
   * @param sink the alert target
   * @param minimumSeverity the inclusive severity threshold
   */
  public JCustosAlertPublisher(JCustosAlertSink sink,
      JCustosEventSeverity minimumSeverity) {
    this.sink = Objects.requireNonNull(sink, "sink");
    this.minimumSeverity = Objects.requireNonNull(minimumSeverity, "minimumSeverity");
  }

  @Override
  public void onJCustosEvent(JCustosEvent event) {
    if (event == null || event.severity().compareTo(minimumSeverity) < 0) {
      return;
    }
    JCustosAlert alert = new JCustosAlert(event.eventType(), event.severity(),
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
  public Registration subscribeTo(JCustosEventBus bus) {
    return bus.subscribe(JCustosEvent.class, this);
  }

  // The detail is a short scrubbed reason, never payload content. For a
  // ListenerFailedEvent the failing listener and its failure code are the
  // reason, so they are included (individually scrubbed — CWE-117).
  private static String detailOf(JCustosEvent event) {
    if (event instanceof ListenerFailedEvent failed) {
      return failed.getClass().getSimpleName()
          + " listener=" + LogFieldScrubber.scrub(failed.listenerName())
          + " failure=" + LogFieldScrubber.scrub(failed.failureCode());
    }
    return event.getClass().getSimpleName();
  }
}
