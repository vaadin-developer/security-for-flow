package eu.jsentinel.jcustos.events.otel;

/*-
 * #%L
 * jCustos Events — OpenTelemetry exporter
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.types.DeadLetteredEvent;
import eu.jsentinel.jcustos.events.types.EnvelopeRejectedEvent;
import eu.jsentinel.jcustos.events.types.ListenerFailedEvent;
import eu.jsentinel.jcustos.events.types.ReplayDetectedEvent;
import eu.jsentinel.jcustos.events.types.SequenceViolationEvent;
import eu.jsentinel.jcustos.events.types.SignatureInvalidEvent;
import io.opentelemetry.api.logs.Severity;

import java.util.Map;
import java.util.Objects;

/**
 * Maps an envelope's {@link EventType} to an OpenTelemetry log
 * {@link Severity}. The classification is built from the event records'
 * {@code TYPE} constants — never from duplicated type strings — so it cannot
 * drift from the events module.
 * <p>
 * Deliberately module-local: the SIEM exporter keeps its own numeric CEF/LEEF
 * mapping over the same {@code TYPE} constants; the shared home of the
 * classification is the record constants themselves.
 * <p>
 * Grades: a detected replay maps to {@link Severity#ERROR2} — one honest
 * grade above the other verification failures, mirroring the event's
 * {@code CRITICAL} bus severity (not {@code FATAL}: nothing terminated).
 * Listener failures are operational degradation, not integrity loss —
 * {@link Severity#WARN}. Everything else is {@link Severity#INFO}.
 *
 * @since 00.80.00
 */
@ExperimentalJCustosApi
public final class OtelSeverityHints {

  private static final Map<EventType, Severity> HINTS = Map.of(
      ReplayDetectedEvent.TYPE, Severity.ERROR2,
      SignatureInvalidEvent.TYPE, Severity.ERROR,
      EnvelopeRejectedEvent.TYPE, Severity.ERROR,
      SequenceViolationEvent.TYPE, Severity.ERROR,
      DeadLetteredEvent.TYPE, Severity.ERROR,
      ListenerFailedEvent.TYPE, Severity.WARN);

  private OtelSeverityHints() {
  }

  /**
   * @param eventType the envelope's event type
   * @return the log severity for the type; {@link Severity#INFO} for every
   *     type outside the integrity/self-observability family
   */
  public static Severity severityFor(EventType eventType) {
    Objects.requireNonNull(eventType, "eventType");
    return HINTS.getOrDefault(eventType, Severity.INFO);
  }
}
