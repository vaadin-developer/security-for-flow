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

import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Objects;
import java.util.function.Function;

/**
 * Loads {@link LoginAttemptConfiguration} from system properties and
 * environment variables, with a caller-supplied default.
 *
 * <h2>Sources, in order of precedence</h2>
 * <ol>
 *   <li>System property (highest)</li>
 *   <li>Environment variable</li>
 *   <li>Caller-provided default (lowest)</li>
 * </ol>
 *
 * <h2>Keys</h2>
 * <table>
 *   <caption>Configuration keys (default scope = login endpoint)</caption>
 *   <tr><th>System property</th><th>Environment variable</th></tr>
 *   <tr><td>{@code security.login.attempts.threshold}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_THRESHOLD}</td></tr>
 *   <tr><td>{@code security.login.attempts.window}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_WINDOW}</td></tr>
 *   <tr><td>{@code security.login.attempts.initial-lockout}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_INITIAL_LOCKOUT}</td></tr>
 *   <tr><td>{@code security.login.attempts.max-lockout}</td>
 *       <td>{@code SECURITY_LOGIN_ATTEMPTS_MAX_LOCKOUT}</td></tr>
 * </table>
 *
 * <p>Duration values are parsed as ISO-8601 (e.g. {@code PT5M},
 * {@code PT1H}). The {@link #forBootstrap()} variant uses
 * {@code security.bootstrap.attempts.*} prefixes so the bootstrap
 * endpoint can be tuned independently of the normal login endpoint.
 *
 * <p>Invalid values fail fast with {@link IllegalArgumentException}.
 */
public final class LoginAttemptConfigurationLoader {

  public static final String LOGIN_THRESHOLD_PROPERTY = "security.login.attempts.threshold";
  public static final String LOGIN_THRESHOLD_ENV = "SECURITY_LOGIN_ATTEMPTS_THRESHOLD";
  public static final String LOGIN_WINDOW_PROPERTY = "security.login.attempts.window";
  public static final String LOGIN_WINDOW_ENV = "SECURITY_LOGIN_ATTEMPTS_WINDOW";
  public static final String LOGIN_INITIAL_LOCKOUT_PROPERTY = "security.login.attempts.initial-lockout";
  public static final String LOGIN_INITIAL_LOCKOUT_ENV = "SECURITY_LOGIN_ATTEMPTS_INITIAL_LOCKOUT";
  public static final String LOGIN_MAX_LOCKOUT_PROPERTY = "security.login.attempts.max-lockout";
  public static final String LOGIN_MAX_LOCKOUT_ENV = "SECURITY_LOGIN_ATTEMPTS_MAX_LOCKOUT";

  public static final String BOOTSTRAP_THRESHOLD_PROPERTY = "security.bootstrap.attempts.threshold";
  public static final String BOOTSTRAP_THRESHOLD_ENV = "SECURITY_BOOTSTRAP_ATTEMPTS_THRESHOLD";
  public static final String BOOTSTRAP_WINDOW_PROPERTY = "security.bootstrap.attempts.window";
  public static final String BOOTSTRAP_WINDOW_ENV = "SECURITY_BOOTSTRAP_ATTEMPTS_WINDOW";
  public static final String BOOTSTRAP_INITIAL_LOCKOUT_PROPERTY = "security.bootstrap.attempts.initial-lockout";
  public static final String BOOTSTRAP_INITIAL_LOCKOUT_ENV = "SECURITY_BOOTSTRAP_ATTEMPTS_INITIAL_LOCKOUT";
  public static final String BOOTSTRAP_MAX_LOCKOUT_PROPERTY = "security.bootstrap.attempts.max-lockout";
  public static final String BOOTSTRAP_MAX_LOCKOUT_ENV = "SECURITY_BOOTSTRAP_ATTEMPTS_MAX_LOCKOUT";

  private final Function<String, String> sysprop;
  private final Function<String, String> env;

  /** Default loader reading from {@link System#getProperty} and {@link System#getenv}. */
  public LoginAttemptConfigurationLoader() {
    this(System::getProperty, System::getenv);
  }

  /**
   * Test seam: inject custom sources.
   *
   * @param sysprop function returning system-property values (typically
   *                {@link System#getProperty})
   * @param env     function returning environment-variable values
   *                (typically {@link System#getenv})
   */
  public LoginAttemptConfigurationLoader(
      Function<String, String> sysprop,
      Function<String, String> env) {
    this.sysprop = Objects.requireNonNull(sysprop, "sysprop");
    this.env = Objects.requireNonNull(env, "env");
  }

  /**
   * Loads configuration for the standard login endpoint, falling back to
   * {@link LoginAttemptConfiguration#defaults()} when no source supplies
   * a value.
   */
  public LoginAttemptConfiguration forLogin() {
    return load(
        LoginAttemptConfiguration.defaults(),
        LOGIN_THRESHOLD_PROPERTY, LOGIN_THRESHOLD_ENV,
        LOGIN_WINDOW_PROPERTY, LOGIN_WINDOW_ENV,
        LOGIN_INITIAL_LOCKOUT_PROPERTY, LOGIN_INITIAL_LOCKOUT_ENV,
        LOGIN_MAX_LOCKOUT_PROPERTY, LOGIN_MAX_LOCKOUT_ENV);
  }

  /**
   * Loads configuration for the bootstrap-admin endpoint, falling back
   * to {@link LoginAttemptConfiguration#strictBootstrap()} when no
   * source supplies a value.
   */
  public LoginAttemptConfiguration forBootstrap() {
    return load(
        LoginAttemptConfiguration.strictBootstrap(),
        BOOTSTRAP_THRESHOLD_PROPERTY, BOOTSTRAP_THRESHOLD_ENV,
        BOOTSTRAP_WINDOW_PROPERTY, BOOTSTRAP_WINDOW_ENV,
        BOOTSTRAP_INITIAL_LOCKOUT_PROPERTY, BOOTSTRAP_INITIAL_LOCKOUT_ENV,
        BOOTSTRAP_MAX_LOCKOUT_PROPERTY, BOOTSTRAP_MAX_LOCKOUT_ENV);
  }

  private LoginAttemptConfiguration load(
      LoginAttemptConfiguration defaults,
      String thresholdProp, String thresholdEnv,
      String windowProp, String windowEnv,
      String initialProp, String initialEnv,
      String maxProp, String maxEnv) {
    int threshold = readThreshold(thresholdProp, thresholdEnv, defaults.failureThreshold());
    Duration window = readDuration(windowProp, windowEnv, defaults.window());
    Duration initial = readDuration(initialProp, initialEnv, defaults.initialLockout());
    Duration max = readDuration(maxProp, maxEnv, defaults.maxLockout());
    return new LoginAttemptConfiguration(threshold, window, initial, max);
  }

  private int readThreshold(String property, String envVar, int defaultValue) {
    String value = firstNonBlank(sysprop.apply(property), env.apply(envVar));
    if (value == null) {
      return defaultValue;
    }
    try {
      int parsed = Integer.parseInt(value.trim());
      if (parsed < 1) {
        throw new IllegalArgumentException(
            "Login attempt threshold must be >= 1: " + value);
      }
      return parsed;
    } catch (NumberFormatException e) {
      throw new IllegalArgumentException(
          "Invalid login attempt threshold '" + value + "'. Expected a positive integer.", e);
    }
  }

  private Duration readDuration(String property, String envVar, Duration defaultValue) {
    String value = firstNonBlank(sysprop.apply(property), env.apply(envVar));
    if (value == null) {
      return defaultValue;
    }
    try {
      Duration parsed = Duration.parse(value.trim());
      if (parsed.isNegative() || parsed.isZero()) {
        throw new IllegalArgumentException(
            "Login attempt duration must be positive: " + value);
      }
      return parsed;
    } catch (DateTimeParseException e) {
      throw new IllegalArgumentException(
          "Invalid login attempt duration '" + value
              + "'. Expected ISO-8601 (e.g. PT5M, PT1H).", e);
    }
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) {
      return a;
    }
    if (b != null && !b.isBlank()) {
      return b;
    }
    return null;
  }
}
