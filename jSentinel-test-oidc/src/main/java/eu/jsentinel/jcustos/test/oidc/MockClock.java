/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package eu.jsentinel.jcustos.test.oidc;

import java.time.Duration;
import java.time.Instant;
import java.util.function.Supplier;

/**
 * A controllable clock for deterministic OIDC tests (V00.79) — a
 * {@code Supplier<Instant>} whose value only changes when the test advances it.
 * The jSentinel time-dependent components (validators, pollers, caches) all take a
 * {@code Supplier<Instant>}, so {@code MockClock} drops in directly.
 */
public final class MockClock implements Supplier<Instant> {

  private volatile Instant now;

  public MockClock(Instant start) {
    this.now = java.util.Objects.requireNonNull(start, "start");
  }

  /** A clock fixed at {@code 2026-06-27T12:00:00Z}. */
  public static MockClock fixed() {
    return new MockClock(Instant.parse("2026-06-27T12:00:00Z"));
  }

  @Override
  public Instant get() {
    return now;
  }

  /** Advances the clock by {@code duration} and returns the new instant. */
  public Instant advance(Duration duration) {
    this.now = now.plus(java.util.Objects.requireNonNull(duration, "duration"));
    return now;
  }

  /** Sets the clock to an absolute instant. */
  public void set(Instant instant) {
    this.now = java.util.Objects.requireNonNull(instant, "instant");
  }
}
