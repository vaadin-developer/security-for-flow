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
package com.svenruppert.vaadin.security.bruteforce;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LoginAttemptConfigurationLoaderTest {

  @Test
  @DisplayName("forLogin: returns defaults when no source supplies a value")
  void forLoginDefault() {
    LoginAttemptConfigurationLoader loader = loaderOf(Map.of(), Map.of());

    LoginAttemptConfiguration c = loader.forLogin();

    assertEquals(LoginAttemptConfiguration.defaults(), c);
  }

  @Test
  @DisplayName("forBootstrap: returns strict defaults when no source supplies a value")
  void forBootstrapDefault() {
    LoginAttemptConfigurationLoader loader = loaderOf(Map.of(), Map.of());

    LoginAttemptConfiguration c = loader.forBootstrap();

    assertEquals(LoginAttemptConfiguration.strictBootstrap(), c);
  }

  @Test
  @DisplayName("system property overrides default and env")
  void sysPropWins() {
    Map<String, String> sys = Map.of(
        LoginAttemptConfigurationLoader.LOGIN_THRESHOLD_PROPERTY, "10");
    Map<String, String> env = Map.of(
        LoginAttemptConfigurationLoader.LOGIN_THRESHOLD_ENV, "20");

    LoginAttemptConfigurationLoader loader = loaderOf(sys, env);

    assertEquals(10, loader.forLogin().failureThreshold());
  }

  @Test
  @DisplayName("env variable wins over default when sysprop is absent")
  void envOverridesDefault() {
    Map<String, String> env = Map.of(
        LoginAttemptConfigurationLoader.LOGIN_THRESHOLD_ENV, "9");

    LoginAttemptConfigurationLoader loader = loaderOf(Map.of(), env);

    assertEquals(9, loader.forLogin().failureThreshold());
  }

  @Test
  @DisplayName("ISO-8601 durations are parsed for window/initial/max")
  void parsesDurations() {
    Map<String, String> sys = new HashMap<>();
    sys.put(LoginAttemptConfigurationLoader.LOGIN_WINDOW_PROPERTY, "PT10M");
    sys.put(LoginAttemptConfigurationLoader.LOGIN_INITIAL_LOCKOUT_PROPERTY, "PT5M");
    sys.put(LoginAttemptConfigurationLoader.LOGIN_MAX_LOCKOUT_PROPERTY, "PT2H");

    LoginAttemptConfigurationLoader loader = loaderOf(sys, Map.of());

    LoginAttemptConfiguration c = loader.forLogin();
    assertEquals(Duration.ofMinutes(10), c.window());
    assertEquals(Duration.ofMinutes(5), c.initialLockout());
    assertEquals(Duration.ofHours(2), c.maxLockout());
  }

  @Test
  @DisplayName("threshold below 1 fails fast")
  void rejectsBadThreshold() {
    Map<String, String> sys = Map.of(
        LoginAttemptConfigurationLoader.LOGIN_THRESHOLD_PROPERTY, "0");

    LoginAttemptConfigurationLoader loader = loaderOf(sys, Map.of());

    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        loader::forLogin);
    assertTrue(e.getMessage().contains("threshold"));
  }

  @Test
  @DisplayName("non-numeric threshold fails fast with a usable message")
  void rejectsNonNumericThreshold() {
    Map<String, String> sys = Map.of(
        LoginAttemptConfigurationLoader.LOGIN_THRESHOLD_PROPERTY, "not-a-number");

    LoginAttemptConfigurationLoader loader = loaderOf(sys, Map.of());

    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        loader::forLogin);
    assertTrue(e.getMessage().contains("not-a-number"));
  }

  @Test
  @DisplayName("non-ISO-8601 duration fails fast")
  void rejectsBadDuration() {
    Map<String, String> sys = Map.of(
        LoginAttemptConfigurationLoader.LOGIN_WINDOW_PROPERTY, "5 minutes");

    LoginAttemptConfigurationLoader loader = loaderOf(sys, Map.of());

    IllegalArgumentException e = assertThrows(IllegalArgumentException.class,
        loader::forLogin);
    assertTrue(e.getMessage().contains("ISO-8601"));
  }

  @Test
  @DisplayName("zero or negative duration fails fast")
  void rejectsZeroDuration() {
    Map<String, String> sys = Map.of(
        LoginAttemptConfigurationLoader.LOGIN_INITIAL_LOCKOUT_PROPERTY, "PT0S");

    LoginAttemptConfigurationLoader loader = loaderOf(sys, Map.of());

    assertThrows(IllegalArgumentException.class, loader::forLogin);
  }

  @Test
  @DisplayName("bootstrap variant uses its own keys, independent of login keys")
  void bootstrapIndependence() {
    Map<String, String> sys = new HashMap<>();
    sys.put(LoginAttemptConfigurationLoader.LOGIN_THRESHOLD_PROPERTY, "20");
    sys.put(LoginAttemptConfigurationLoader.BOOTSTRAP_THRESHOLD_PROPERTY, "2");

    LoginAttemptConfigurationLoader loader = loaderOf(sys, Map.of());

    assertEquals(20, loader.forLogin().failureThreshold());
    assertEquals(2, loader.forBootstrap().failureThreshold());
  }

  @Test
  @DisplayName("blank sysprop value falls through to env, then default")
  void blankFallsThrough() {
    Map<String, String> sys = Map.of(
        LoginAttemptConfigurationLoader.LOGIN_THRESHOLD_PROPERTY, "   ");
    Map<String, String> env = Map.of(
        LoginAttemptConfigurationLoader.LOGIN_THRESHOLD_ENV, "7");

    LoginAttemptConfigurationLoader loader = loaderOf(sys, env);

    assertEquals(7, loader.forLogin().failureThreshold());
  }

  private static LoginAttemptConfigurationLoader loaderOf(
      Map<String, String> sys, Map<String, String> env) {
    return new LoginAttemptConfigurationLoader(sys::get, env::get);
  }
}
