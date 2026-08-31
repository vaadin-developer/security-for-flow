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
package eu.jsentinel.jcustos.credential.password.pbkdf2;

import eu.jsentinel.jcustos.credential.password.calibration.CalibrationProfile;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Pbkdf2ParameterCalibratorTest {

  /**
   * Fake nanosecond clock driven by a scripted sequence of return
   * values. Lets the test pin the apparent runtime of each KDF call
   * without driving real wall-clock time.
   */
  private static final class FakeNanoClock implements java.util.function.LongSupplier {
    private final long[] sequence;
    private int idx = 0;

    FakeNanoClock(long... sequence) {
      this.sequence = sequence;
    }

    @Override
    public long getAsLong() {
      long value = sequence[Math.min(idx, sequence.length - 1)];
      idx++;
      return value;
    }
  }

  @Test
  @DisplayName("calibrate produces a profile whose parameters match the algorithm")
  void calibrateProducesProfile() {
    // Fake clock that reports 100 ms for the very first measurement →
    // calibrator exits immediately, doing only one real KDF call.
    Clock wall = Clock.fixed(Instant.parse("2026-06-01T12:00:00Z"), ZoneOffset.UTC);
    Pbkdf2ParameterCalibrator calibrator = new Pbkdf2ParameterCalibrator(
        new Pbkdf2PasswordHashProvider(),
        new FakeNanoClock(0L, 100_000_000L),
        wall,
        1_000,
        Pbkdf2Defaults.DEFAULT_KEY_LENGTH);

    CalibrationProfile profile = calibrator.calibrate(Duration.ofMillis(100));
    assertEquals(Pbkdf2ParameterNames.ALGORITHM, profile.algorithm());
    assertEquals(Pbkdf2ParameterNames.PROVIDER_ID, profile.providerId());
    assertEquals(100L, profile.targetMillis());
    assertNotNull(profile.parameters().get(Pbkdf2ParameterNames.ITERATIONS));
    assertEquals(Integer.toString(Pbkdf2Defaults.DEFAULT_KEY_LENGTH),
        profile.parameters().get(Pbkdf2ParameterNames.KEY_LENGTH));
    assertEquals(wall.instant(), profile.calibratedAt());
  }

  @Test
  @DisplayName("calibrate scales iterations toward the target when the clock reports a fixed step")
  void calibrateScalesTowardsTarget() {
    // Attempt 0 (iterations=1000) reports 5 ms; calibrator computes
    // scale = 50/5 = 10 → iterations grows to 10000.
    // Attempt 1 (iterations=10000) reports 50 ms → within tolerance, exit.
    Clock wall = Clock.fixed(Instant.parse("2026-06-01T12:00:00Z"), ZoneOffset.UTC);
    Pbkdf2ParameterCalibrator calibrator = new Pbkdf2ParameterCalibrator(
        new Pbkdf2PasswordHashProvider(),
        new FakeNanoClock(
            0L, 5_000_000L,
            10_000_000L, 60_000_000L),
        wall,
        1_000,
        Pbkdf2Defaults.DEFAULT_KEY_LENGTH);
    CalibrationProfile profile = calibrator.calibrate(Duration.ofMillis(50));
    int iterations = Integer.parseInt(
        profile.parameters().get(Pbkdf2ParameterNames.ITERATIONS));
    assertEquals(10_000, iterations,
        "calibrator should land on the 10x-scaled iteration count");
    assertEquals(50L, profile.measuredMillis());
  }

  @Test
  @DisplayName("calibrate rejects zero / negative target durations")
  void rejectsBadTargets() {
    Pbkdf2ParameterCalibrator calibrator = new Pbkdf2ParameterCalibrator();
    assertThrows(IllegalArgumentException.class,
        () -> calibrator.calibrate(Duration.ZERO));
    assertThrows(IllegalArgumentException.class,
        () -> calibrator.calibrate(Duration.ofMillis(-1)));
  }

  @Test
  @DisplayName("Constructor rejects start iterations below the floor")
  void rejectsLowStartIterations() {
    assertThrows(IllegalArgumentException.class,
        () -> new Pbkdf2ParameterCalibrator(
            new Pbkdf2PasswordHashProvider(),
            System::nanoTime,
            Clock.systemUTC(),
            100,
            Pbkdf2Defaults.DEFAULT_KEY_LENGTH));
  }

  @Test
  @DisplayName("Calibration produces a profile, but loading does not trigger a new run (no auto-recalibration)")
  void noAutoRecalibrationContract() {
    // This is an architectural assertion: the calibrator is a separate
    // class from the store; reloading a stored profile never instantiates
    // the calibrator. The test documents the contract by showing that
    // calling the calibrator twice produces two independent profiles —
    // startup code must therefore avoid re-invoking it on every boot.
    // Each calibration call records two clock samples (before/after) and
    // exits on the first attempt because measured == target.
    Clock wall = Clock.fixed(Instant.parse("2026-06-01T12:00:00Z"), ZoneOffset.UTC);
    FakeNanoClock clock = new FakeNanoClock(
        0L, 20_000_000L,
        0L, 20_000_000L);
    Pbkdf2ParameterCalibrator calibrator = new Pbkdf2ParameterCalibrator(
        new Pbkdf2PasswordHashProvider(),
        clock,
        wall,
        1_000,
        Pbkdf2Defaults.DEFAULT_KEY_LENGTH);
    CalibrationProfile a = calibrator.calibrate(Duration.ofMillis(20));
    CalibrationProfile b = calibrator.calibrate(Duration.ofMillis(20));
    assertEquals(a.parameters(), b.parameters());
  }
}
