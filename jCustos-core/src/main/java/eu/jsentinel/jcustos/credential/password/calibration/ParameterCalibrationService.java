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
package eu.jsentinel.jcustos.credential.password.calibration;

import java.time.Duration;

/**
 * Produces a {@link CalibrationProfile} for a specific algorithm by
 * running the underlying KDF and measuring its runtime.
 *
 * <p>Implementations are intentionally algorithm-specific: each KDF
 * has its own dominant cost knob (PBKDF2 iterations, Argon2id memory,
 * scrypt N) and its own admissible-value rules.</p>
 *
 * <p>Calibration is an offline / operator-driven activity. Production
 * code must <em>not</em> call this on every startup &mdash; the result
 * should be persisted through {@link CalibrationProfileStore} and
 * reloaded thereafter (CWE-754).</p>
 */
public interface ParameterCalibrationService {

  /**
   * @param target  desired verification runtime (e.g. 250&nbsp;ms)
   * @return calibrated profile whose parameters approximate the target
   *         within the implementation's tolerance
   */
  CalibrationProfile calibrate(Duration target);
}
