/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
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
package eu.jsentinel.jcustos.credential.password.calibration;

import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Reproducible calibration result for a single password-hash algorithm.
 *
 * <p>Operators run the calibrator once for a target verification time
 * (typically 200–500&nbsp;ms) and persist the resulting profile. At
 * startup the policy loads the profile and uses its parameters; the
 * system <em>never</em> calibrates silently on every startup (a quiet
 * recalibration would defeat reproducibility and make rehash decisions
 * non-deterministic, CWE-754).</p>
 *
 * @param algorithm           canonical algorithm identifier
 * @param providerId          provider that produced the profile
 * @param parameters          calibrated parameter map (defensive copy,
 *                            unmodifiable)
 * @param targetMillis        the runtime the operator asked for
 * @param measuredMillis      the runtime actually achieved with
 *                            {@code parameters} during calibration
 * @param calibratedAt        instant the calibration finished
 */
public record CalibrationProfile(
    String algorithm,
    String providerId,
    Map<String, String> parameters,
    long targetMillis,
    long measuredMillis,
    Instant calibratedAt
) {

  public CalibrationProfile {
    Objects.requireNonNull(algorithm, "algorithm");
    if (algorithm.isBlank()) {
      throw new IllegalArgumentException("algorithm must not be blank");
    }
    Objects.requireNonNull(providerId, "providerId");
    if (providerId.isBlank()) {
      throw new IllegalArgumentException("providerId must not be blank");
    }
    Objects.requireNonNull(parameters, "parameters");
    parameters = Collections.unmodifiableMap(new LinkedHashMap<>(parameters));
    if (targetMillis <= 0L) {
      throw new IllegalArgumentException("targetMillis must be positive");
    }
    if (measuredMillis < 0L) {
      throw new IllegalArgumentException("measuredMillis must be >= 0");
    }
    Objects.requireNonNull(calibratedAt, "calibratedAt");
  }
}
