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
package eu.jsentinel.jcustos.credential.password.pbkdf2;

import eu.jsentinel.jcustos.credential.password.calibration.CalibrationProfile;
import eu.jsentinel.jcustos.credential.password.calibration.ParameterCalibrationService;
import eu.jsentinel.jcustos.credential.password.policy.DefaultPasswordHashPolicy;
import eu.jsentinel.jcustos.credential.password.policy.PasswordHashPolicy;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.LongSupplier;

/**
 * Calibrates the PBKDF2-HMAC-SHA-256 iteration count for a target
 * verification runtime.
 *
 * <p>The calibrator scales {@code iterations} linearly: it picks a
 * starting iteration count, measures one hash, scales by the runtime
 * ratio, measures again, and stops once the runtime is within ±10%% of
 * the target or after a small cap on attempts. The result is the
 * {@link CalibrationProfile} the operator persists; production code
 * reloads the profile through {@link eu.jsentinel.jcustos.credential.password.calibration.CalibrationProfileStore}
 * and never recalibrates on startup (CWE-754).</p>
 */
public final class Pbkdf2ParameterCalibrator implements ParameterCalibrationService {

  private static final int MIN_ATTEMPT_ITERATIONS = 1_000;
  private static final int MAX_ATTEMPT_ITERATIONS = 50_000_000;
  private static final int MAX_ATTEMPTS = 8;

  private final Pbkdf2PasswordHashProvider provider;
  private final LongSupplier clockNanos;
  private final Clock wallClock;
  private final int startIterations;
  private final int keyLengthBytes;

  public Pbkdf2ParameterCalibrator() {
    this(new Pbkdf2PasswordHashProvider(),
        System::nanoTime,
        Clock.systemUTC(),
        Pbkdf2Defaults.MIN_ITERATIONS,
        Pbkdf2Defaults.DEFAULT_KEY_LENGTH);
  }

  public Pbkdf2ParameterCalibrator(
      Pbkdf2PasswordHashProvider provider,
      LongSupplier clockNanos,
      Clock wallClock,
      int startIterations,
      int keyLengthBytes) {
    this.provider = Objects.requireNonNull(provider, "provider");
    this.clockNanos = Objects.requireNonNull(clockNanos, "clockNanos");
    this.wallClock = Objects.requireNonNull(wallClock, "wallClock");
    if (startIterations < MIN_ATTEMPT_ITERATIONS) {
      throw new IllegalArgumentException(
          "startIterations below " + MIN_ATTEMPT_ITERATIONS);
    }
    this.startIterations = startIterations;
    if (keyLengthBytes < Pbkdf2Defaults.MIN_KEY_LENGTH) {
      throw new IllegalArgumentException(
          "keyLengthBytes below " + Pbkdf2Defaults.MIN_KEY_LENGTH);
    }
    this.keyLengthBytes = keyLengthBytes;
  }

  @Override
  public CalibrationProfile calibrate(Duration target) {
    Objects.requireNonNull(target, "target");
    if (target.isZero() || target.isNegative()) {
      throw new IllegalArgumentException("target must be positive");
    }
    long targetMillis = target.toMillis();
    if (targetMillis <= 0L) {
      throw new IllegalArgumentException("target must be at least 1ms");
    }

    int iterations = startIterations;
    long measuredMillis = -1L;
    char[] sample = "calibration-sample".toCharArray();
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      PasswordHashPolicy policy = buildTransientPolicy(iterations);
      long before = clockNanos.getAsLong();
      provider.hash(sample.clone(), policy, Optional.empty());
      long after = clockNanos.getAsLong();
      measuredMillis = Math.max(0L, (after - before) / 1_000_000L);

      if (withinTolerance(measuredMillis, targetMillis)) {
        break;
      }
      long ratioNumerator = targetMillis * (long) iterations;
      long denominator = Math.max(1L, measuredMillis);
      long scaled = ratioNumerator / denominator;
      iterations = clamp(scaled,
          MIN_ATTEMPT_ITERATIONS, MAX_ATTEMPT_ITERATIONS);
    }

    Map<String, String> calibrated = new LinkedHashMap<>();
    calibrated.put(Pbkdf2ParameterNames.ITERATIONS, Integer.toString(iterations));
    calibrated.put(Pbkdf2ParameterNames.KEY_LENGTH,
        Integer.toString(keyLengthBytes));

    return new CalibrationProfile(
        Pbkdf2ParameterNames.ALGORITHM,
        Pbkdf2ParameterNames.PROVIDER_ID,
        calibrated,
        targetMillis,
        Math.max(0L, measuredMillis),
        Instant.now(wallClock));
  }

  private static boolean withinTolerance(long measured, long target) {
    long delta = Math.abs(measured - target);
    return delta * 10L <= target;
  }

  private static int clamp(long candidate, int min, int max) {
    if (candidate < (long) min) return min;
    if (candidate > (long) max) return max;
    return (int) candidate;
  }

  private PasswordHashPolicy buildTransientPolicy(int iterations) {
    Map<String, String> defaults = new LinkedHashMap<>();
    defaults.put(Pbkdf2ParameterNames.ITERATIONS, Integer.toString(iterations));
    defaults.put(Pbkdf2ParameterNames.KEY_LENGTH,
        Integer.toString(keyLengthBytes));
    Map<String, String> min = new LinkedHashMap<>(defaults);
    min.put(Pbkdf2ParameterNames.SALT_LENGTH,
        Integer.toString(Pbkdf2Defaults.MIN_SALT_LENGTH));
    Map<String, String> max = new LinkedHashMap<>();
    max.put(Pbkdf2ParameterNames.ITERATIONS,
        Integer.toString(MAX_ATTEMPT_ITERATIONS));
    max.put(Pbkdf2ParameterNames.KEY_LENGTH,
        Integer.toString(Pbkdf2Defaults.MAX_KEY_LENGTH));
    max.put(Pbkdf2ParameterNames.SALT_LENGTH,
        Integer.toString(Pbkdf2Defaults.MAX_SALT_LENGTH));
    return DefaultPasswordHashPolicy.builder()
        .policyVersion(1)
        .preferredAlgorithm(Pbkdf2ParameterNames.ALGORITHM)
        .preferredProviderId(Pbkdf2ParameterNames.PROVIDER_ID)
        .defaultParameters(Pbkdf2ParameterNames.ALGORITHM, defaults)
        .minimumParameters(Pbkdf2ParameterNames.ALGORITHM, min)
        .maximumParameters(Pbkdf2ParameterNames.ALGORITHM, max)
        .build();
  }
}
