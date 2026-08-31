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
package eu.jsentinel.jcustos.demo.restclient.backend;

import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.Objects;

/**
 * Backend connection configuration. Reads system properties (preferred)
 * with environment-variable fallback and demo defaults.
 *
 * <table>
 *   <caption>Configuration keys</caption>
 *   <tr><th>System property</th><th>Environment variable</th><th>Default</th></tr>
 *   <tr><td>{@code demo.backend.url}</td>
 *       <td>{@code DEMO_BACKEND_URL}</td>
 *       <td>{@code http://localhost:8080}</td></tr>
 *   <tr><td>{@code demo.backend.connect-timeout}</td>
 *       <td>{@code DEMO_BACKEND_CONNECT_TIMEOUT}</td>
 *       <td>{@code PT5S}</td></tr>
 *   <tr><td>{@code demo.backend.request-timeout}</td>
 *       <td>{@code DEMO_BACKEND_REQUEST_TIMEOUT}</td>
 *       <td>{@code PT10S}</td></tr>
 * </table>
 */
public record BackendConfig(String baseUrl, Duration connectTimeout, Duration requestTimeout) {

  public static final String URL_PROPERTY = "demo.backend.url";
  public static final String URL_ENV = "DEMO_BACKEND_URL";
  public static final String CONNECT_TIMEOUT_PROPERTY = "demo.backend.connect-timeout";
  public static final String CONNECT_TIMEOUT_ENV = "DEMO_BACKEND_CONNECT_TIMEOUT";
  public static final String REQUEST_TIMEOUT_PROPERTY = "demo.backend.request-timeout";
  public static final String REQUEST_TIMEOUT_ENV = "DEMO_BACKEND_REQUEST_TIMEOUT";

  public static final String DEFAULT_BASE_URL = "http://localhost:8080";
  public static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(5);
  public static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(10);

  public BackendConfig {
    Objects.requireNonNull(baseUrl, "baseUrl");
    if (baseUrl.isBlank()) {
      throw new IllegalArgumentException("baseUrl must not be blank");
    }
    if (baseUrl.endsWith("/")) {
      baseUrl = baseUrl.substring(0, baseUrl.length() - 1);
    }
    Objects.requireNonNull(connectTimeout, "connectTimeout");
    Objects.requireNonNull(requestTimeout, "requestTimeout");
    if (connectTimeout.isNegative() || connectTimeout.isZero()) {
      throw new IllegalArgumentException("connectTimeout must be positive");
    }
    if (requestTimeout.isNegative() || requestTimeout.isZero()) {
      throw new IllegalArgumentException("requestTimeout must be positive");
    }
  }

  public static BackendConfig fromEnvironment() {
    String url = firstNonBlank(System.getProperty(URL_PROPERTY), System.getenv(URL_ENV));
    if (url == null) url = DEFAULT_BASE_URL;
    Duration connect = readDuration(CONNECT_TIMEOUT_PROPERTY, CONNECT_TIMEOUT_ENV, DEFAULT_CONNECT_TIMEOUT);
    Duration request = readDuration(REQUEST_TIMEOUT_PROPERTY, REQUEST_TIMEOUT_ENV, DEFAULT_REQUEST_TIMEOUT);
    return new BackendConfig(url, connect, request);
  }

  private static Duration readDuration(String property, String env, Duration fallback) {
    String raw = firstNonBlank(System.getProperty(property), System.getenv(env));
    if (raw == null) return fallback;
    try {
      return Duration.parse(raw.trim());
    } catch (DateTimeParseException e) {
      throw new IllegalArgumentException(
          "Invalid duration '" + raw + "' for " + property
              + ". Expected ISO-8601 (e.g. PT5S, PT10S).", e);
    }
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) return a;
    if (b != null && !b.isBlank()) return b;
    return null;
  }
}
