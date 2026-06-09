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
package com.svenruppert.jsentinel.bruteforce;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoginAttemptConfigurationTest {

  @Test
  @DisplayName("defaults() reflects the documented login-endpoint thresholds")
  void loginDefaults() {
    LoginAttemptConfiguration c = LoginAttemptConfiguration.defaults();
    assertEquals(5, c.failureThreshold());
    assertEquals(Duration.ofMinutes(15), c.window());
    assertEquals(Duration.ofMinutes(15), c.initialLockout());
    assertEquals(Duration.ofHours(4), c.maxLockout());
  }

  @Test
  @DisplayName("strictBootstrap() is meaningfully stricter than the login defaults")
  void bootstrapStrictDefaults() {
    LoginAttemptConfiguration login = LoginAttemptConfiguration.defaults();
    LoginAttemptConfiguration boot = LoginAttemptConfiguration.strictBootstrap();

    assertTrue(boot.failureThreshold() < login.failureThreshold(),
        "bootstrap threshold must be < login threshold");
    assertTrue(boot.maxLockout().compareTo(login.maxLockout()) > 0,
        "bootstrap max lockout must be > login max lockout");
  }

  @Test
  @DisplayName("constructor rejects threshold < 1")
  void rejectsZeroThreshold() {
    assertThrows(IllegalArgumentException.class,
        () -> new LoginAttemptConfiguration(
            0, Duration.ofMinutes(1), Duration.ofMinutes(1), Duration.ofMinutes(1)));
  }

  @Test
  @DisplayName("constructor rejects null durations")
  void rejectsNullDurations() {
    assertThrows(NullPointerException.class,
        () -> new LoginAttemptConfiguration(
            3, null, Duration.ofMinutes(1), Duration.ofMinutes(1)));
    assertThrows(NullPointerException.class,
        () -> new LoginAttemptConfiguration(
            3, Duration.ofMinutes(1), null, Duration.ofMinutes(1)));
    assertThrows(NullPointerException.class,
        () -> new LoginAttemptConfiguration(
            3, Duration.ofMinutes(1), Duration.ofMinutes(1), null));
  }

  @Test
  @DisplayName("constructor rejects non-positive window / initialLockout")
  void rejectsZeroDurations() {
    assertThrows(IllegalArgumentException.class,
        () -> new LoginAttemptConfiguration(
            3, Duration.ZERO, Duration.ofMinutes(1), Duration.ofMinutes(1)));
    assertThrows(IllegalArgumentException.class,
        () -> new LoginAttemptConfiguration(
            3, Duration.ofMinutes(1), Duration.ZERO, Duration.ofMinutes(1)));
  }

  @Test
  @DisplayName("constructor rejects maxLockout < initialLockout")
  void rejectsInverseLockoutBounds() {
    assertThrows(IllegalArgumentException.class,
        () -> new LoginAttemptConfiguration(
            3, Duration.ofMinutes(5),
            Duration.ofMinutes(10),
            Duration.ofMinutes(5)));
  }
}
