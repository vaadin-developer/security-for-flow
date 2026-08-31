/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.abuse;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Privacy-minimised signal emitted by an
 * {@link AbusePatternMonitor} detector when a pattern crosses its
 * threshold.
 *
 * <p>The signal carries <em>aggregates</em> only — counts of distinct
 * usernames / clients, never the usernames or addresses themselves
 * (CWE-359). Audit sinks may add their own metadata if the operator
 * decides that's acceptable for their deployment, but the signal
 * itself stays minimal.</p>
 *
 * @param pattern         which pattern fired
 * @param at              when the signal was raised
 * @param windowSize      sliding-window length the count was measured
 *                        across
 * @param distinctTargets size of the distinct-target set (e.g.
 *                        distinct usernames for SPRAYING, distinct
 *                        clients for STUFFING)
 * @param attempts        total attempts in the window (≥ distinctTargets)
 */
public record AbusePatternSignal(
    AbusePattern pattern,
    Instant at,
    Duration windowSize,
    int distinctTargets,
    int attempts
) {

  public AbusePatternSignal {
    Objects.requireNonNull(pattern, "pattern");
    Objects.requireNonNull(at, "at");
    Objects.requireNonNull(windowSize, "windowSize");
    if (distinctTargets < 1) {
      throw new IllegalArgumentException("distinctTargets must be >= 1");
    }
    if (attempts < distinctTargets) {
      throw new IllegalArgumentException(
          "attempts must be >= distinctTargets");
    }
  }
}
