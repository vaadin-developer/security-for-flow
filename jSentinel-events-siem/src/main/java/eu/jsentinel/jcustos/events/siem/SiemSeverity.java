package eu.jsentinel.jcustos.events.siem;

/*-
 * #%L
 * jSentinel Events — SIEM exporter
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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.events.api.EventType;
import eu.jsentinel.jcustos.events.types.DeadLetteredEvent;
import eu.jsentinel.jcustos.events.types.EnvelopeRejectedEvent;
import eu.jsentinel.jcustos.events.types.ListenerFailedEvent;
import eu.jsentinel.jcustos.events.types.ReplayDetectedEvent;
import eu.jsentinel.jcustos.events.types.SequenceViolationEvent;
import eu.jsentinel.jcustos.events.types.SignatureInvalidEvent;

import java.util.Map;
import java.util.Objects;

/**
 * Maps an envelope's {@link EventType} to the numeric 0–10 severity scale
 * shared by CEF (header severity) and LEEF (the {@code sev} attribute).
 * The classification is built from the event records' {@code TYPE}
 * constants — never from duplicated type strings — so it cannot drift from
 * the events module. Deliberately module-local: the OpenTelemetry exporter
 * keeps its own {@code Severity} mapping over the same constants.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class SiemSeverity {

  /** A detected replay — the concept's critical verification failure. */
  public static final int REPLAY = 10;
  /** Other integrity/verification failures. */
  public static final int INTEGRITY_FAILURE = 9;
  /** Operational degradation (a listener failed), not integrity loss. */
  public static final int DEGRADATION = 6;
  /** Every regular security event. */
  public static final int DEFAULT = 3;

  private static final Map<EventType, Integer> HINTS = Map.of(
      ReplayDetectedEvent.TYPE, REPLAY,
      SignatureInvalidEvent.TYPE, INTEGRITY_FAILURE,
      EnvelopeRejectedEvent.TYPE, INTEGRITY_FAILURE,
      SequenceViolationEvent.TYPE, INTEGRITY_FAILURE,
      DeadLetteredEvent.TYPE, INTEGRITY_FAILURE,
      ListenerFailedEvent.TYPE, DEGRADATION);

  private SiemSeverity() {
  }

  /**
   * @param eventType the envelope's event type
   * @return the 0–10 severity for the type
   */
  public static int severityFor(EventType eventType) {
    Objects.requireNonNull(eventType, "eventType");
    return HINTS.getOrDefault(eventType, DEFAULT);
  }
}
