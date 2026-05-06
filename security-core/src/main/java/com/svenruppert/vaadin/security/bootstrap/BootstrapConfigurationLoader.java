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
package com.svenruppert.vaadin.security.bootstrap;

import java.nio.file.Path;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Objects;
import java.util.function.Function;

/**
 * Loads {@link BootstrapConfiguration} from system properties and environment
 * variables.
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
 *   <caption>Configuration keys</caption>
 *   <tr><th>System property</th><th>Environment variable</th></tr>
 *   <tr><td>{@code security.bootstrap.mode}</td>
 *       <td>{@code SECURITY_BOOTSTRAP_MODE}</td></tr>
 *   <tr><td>{@code security.bootstrap.token.file}</td>
 *       <td>{@code SECURITY_BOOTSTRAP_TOKEN_FILE}</td></tr>
 *   <tr><td>{@code security.bootstrap.token.ttl}</td>
 *       <td>{@code SECURITY_BOOTSTRAP_TOKEN_TTL}</td></tr>
 * </table>
 *
 * <p>The TTL value is parsed as an ISO-8601 duration (e.g. {@code PT15M},
 * {@code PT24H}). If absent, the configuration default applies.
 *
 * <p>Invalid mode values fail fast with {@link IllegalArgumentException}; the
 * caller decides whether to log + fall back or to abort startup.
 */
public final class BootstrapConfigurationLoader {

  public static final String MODE_PROPERTY = "security.bootstrap.mode";
  public static final String MODE_ENV = "SECURITY_BOOTSTRAP_MODE";
  public static final String TOKEN_FILE_PROPERTY = "security.bootstrap.token.file";
  public static final String TOKEN_FILE_ENV = "SECURITY_BOOTSTRAP_TOKEN_FILE";
  public static final String TOKEN_TTL_PROPERTY = "security.bootstrap.token.ttl";
  public static final String TOKEN_TTL_ENV = "SECURITY_BOOTSTRAP_TOKEN_TTL";

  private final Function<String, String> sysprop;
  private final Function<String, String> env;

  /** Default loader reading from {@link System#getProperty} and {@link System#getenv}. */
  public BootstrapConfigurationLoader() {
    this(System::getProperty, System::getenv);
  }

  /** Test seam: inject custom sources. */
  public BootstrapConfigurationLoader(
      Function<String, String> sysprop,
      Function<String, String> env) {
    this.sysprop = Objects.requireNonNull(sysprop, "sysprop");
    this.env = Objects.requireNonNull(env, "env");
  }

  /**
   * Builds a {@link BootstrapConfiguration} from the configured sources.
   *
   * @param defaultMode      mode used when neither sysprop nor env supply one
   * @param defaultTokenFile token file used in {@code PERSISTENT_FILE} mode
   *                         when neither sysprop nor env supply one
   * @param defaultValidity  validity used when no TTL is configured
   * @return resolved configuration
   * @throws IllegalArgumentException if a configured value is unparseable
   */
  public BootstrapConfiguration load(
      BootstrapMode defaultMode,
      Path defaultTokenFile,
      Duration defaultValidity) {
    Objects.requireNonNull(defaultMode, "defaultMode");
    Objects.requireNonNull(defaultValidity, "defaultValidity");
    BootstrapMode mode = readMode(defaultMode);
    Duration validity = readTtl(defaultValidity);
    return switch (mode) {
      case DISABLED -> new BootstrapConfiguration(BootstrapMode.DISABLED, null, validity);
      case TRANSIENT_CONSOLE -> BootstrapConfiguration.transientConsole(validity);
      case PERSISTENT_FILE -> {
        String pathValue = firstNonBlank(sysprop.apply(TOKEN_FILE_PROPERTY), env.apply(TOKEN_FILE_ENV));
        Path path = pathValue != null ? Path.of(pathValue) : defaultTokenFile;
        if (path == null) {
          throw new IllegalArgumentException(
              "PERSISTENT_FILE mode requires a token file path. Set "
                  + TOKEN_FILE_PROPERTY + " or " + TOKEN_FILE_ENV
                  + " or supply a defaultTokenFile.");
        }
        yield BootstrapConfiguration.persistent(path, validity);
      }
    };
  }

  private BootstrapMode readMode(BootstrapMode defaultMode) {
    String value = firstNonBlank(sysprop.apply(MODE_PROPERTY), env.apply(MODE_ENV));
    if (value == null) return defaultMode;
    try {
      return BootstrapMode.valueOf(value.trim().toUpperCase());
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "Invalid bootstrap mode '" + value + "'. Allowed: "
              + "DISABLED, TRANSIENT_CONSOLE, PERSISTENT_FILE", e);
    }
  }

  private Duration readTtl(Duration defaultValidity) {
    String value = firstNonBlank(sysprop.apply(TOKEN_TTL_PROPERTY), env.apply(TOKEN_TTL_ENV));
    if (value == null) return defaultValidity;
    try {
      Duration parsed = Duration.parse(value.trim());
      if (parsed.isNegative() || parsed.isZero()) {
        throw new IllegalArgumentException(
            "Bootstrap token TTL must be positive: " + value);
      }
      return parsed;
    } catch (DateTimeParseException e) {
      throw new IllegalArgumentException(
          "Invalid bootstrap token TTL '" + value
              + "'. Expected ISO-8601 duration, e.g. PT15M, PT24H.", e);
    }
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) return a;
    if (b != null && !b.isBlank()) return b;
    return null;
  }
}
