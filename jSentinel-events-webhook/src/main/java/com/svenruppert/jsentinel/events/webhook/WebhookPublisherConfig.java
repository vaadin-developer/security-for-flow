package com.svenruppert.jsentinel.events.webhook;

/*-
 * #%L
 * jSentinel Events — Webhook exporter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.util.CapacityBound;

import java.net.URI;
import java.time.Duration;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.Supplier;

/**
 * Configuration of a {@link WebhookEventPublisher}. Validated on
 * construction so a misconfigured webhook fails at wiring time, not at the
 * first delivery.
 * <p>
 * Security posture:
 * <ul>
 *   <li><strong>TLS is mandatory for non-loopback targets.</strong> Plain
 *       {@code http} is accepted only for loopback hosts ({@code localhost},
 *       {@code 127.0.0.1}, {@code ::1}) — the exception exists for local
 *       development and honest integration tests. There is deliberately no
 *       global insecure opt-out.</li>
 *   <li><strong>Header-injection guard:</strong> static header names and
 *       values must not contain ISO control characters (CR/LF splitting);
 *       violations are rejected naming the header <em>name</em> only, never
 *       the value.</li>
 *   <li>The bearer token is pulled from {@code bearerTokenSupplier} freshly
 *       per delivery attempt and is never logged.</li>
 * </ul>
 *
 * @param endpoint            webhook target URI ({@code https}, or
 *                            {@code http} on loopback only)
 * @param connectTimeout      HTTP connect timeout
 * @param requestTimeout      per-request timeout
 * @param queueCapacity       bound of the in-memory delivery queue
 * @param maxAttempts         delivery attempts per envelope (&gt;= 1)
 * @param initialBackoff      backoff before the second attempt
 * @param maxBackoff          backoff ceiling (&gt;= {@code initialBackoff})
 * @param staticHeaders       additional headers sent with every request
 * @param bearerTokenSupplier optional bearer token source, consulted per
 *                            attempt; {@link Optional#empty()} sends no
 *                            {@code Authorization} header
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public record WebhookPublisherConfig(
    URI endpoint,
    Duration connectTimeout,
    Duration requestTimeout,
    int queueCapacity,
    int maxAttempts,
    Duration initialBackoff,
    Duration maxBackoff,
    Map<String, String> staticHeaders,
    Supplier<Optional<String>> bearerTokenSupplier) {

  private static final String SCHEME_HTTPS = "https";
  private static final String SCHEME_HTTP = "http";
  private static final Set<String> LOOPBACK_HOSTS =
      Set.of("localhost", "127.0.0.1", "::1", "[::1]");

  private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(5);
  private static final Duration DEFAULT_REQUEST_TIMEOUT = Duration.ofSeconds(10);
  private static final int DEFAULT_QUEUE_CAPACITY = 1024;
  private static final int DEFAULT_MAX_ATTEMPTS = 5;
  private static final Duration DEFAULT_INITIAL_BACKOFF = Duration.ofMillis(500);
  private static final Duration DEFAULT_MAX_BACKOFF = Duration.ofSeconds(30);

  public WebhookPublisherConfig {
    Objects.requireNonNull(endpoint, "endpoint");
    Objects.requireNonNull(connectTimeout, "connectTimeout");
    Objects.requireNonNull(requestTimeout, "requestTimeout");
    Objects.requireNonNull(initialBackoff, "initialBackoff");
    Objects.requireNonNull(maxBackoff, "maxBackoff");
    Objects.requireNonNull(staticHeaders, "staticHeaders");
    Objects.requireNonNull(bearerTokenSupplier, "bearerTokenSupplier");
    requireSecureScheme(endpoint);
    CapacityBound.requirePositiveCapacity(queueCapacity);
    if (maxAttempts < 1) {
      throw new IllegalArgumentException("maxAttempts must be >= 1");
    }
    requirePositive(connectTimeout, "connectTimeout");
    requirePositive(requestTimeout, "requestTimeout");
    requirePositive(initialBackoff, "initialBackoff");
    requirePositive(maxBackoff, "maxBackoff");
    if (maxBackoff.compareTo(initialBackoff) < 0) {
      throw new IllegalArgumentException("maxBackoff must be >= initialBackoff");
    }
    staticHeaders.forEach(WebhookPublisherConfig::requireCleanHeader);
    staticHeaders = Map.copyOf(staticHeaders);
  }

  /**
   * @param endpoint webhook target URI
   * @return a config with production-lean defaults: 5 s connect / 10 s
   *     request timeout, queue capacity 1024, 5 attempts, 500 ms initial and
   *     30 s maximum backoff, no static headers, no bearer token
   */
  public static WebhookPublisherConfig defaults(URI endpoint) {
    return new WebhookPublisherConfig(
        endpoint,
        DEFAULT_CONNECT_TIMEOUT,
        DEFAULT_REQUEST_TIMEOUT,
        DEFAULT_QUEUE_CAPACITY,
        DEFAULT_MAX_ATTEMPTS,
        DEFAULT_INITIAL_BACKOFF,
        DEFAULT_MAX_BACKOFF,
        Map.of(),
        Optional::empty);
  }

  private static void requireSecureScheme(URI endpoint) {
    String scheme = endpoint.getScheme() == null
        ? ""
        : endpoint.getScheme().toLowerCase(Locale.ROOT);
    if (SCHEME_HTTPS.equals(scheme)) {
      return;
    }
    String host = endpoint.getHost() == null
        ? ""
        : endpoint.getHost().toLowerCase(Locale.ROOT);
    if (SCHEME_HTTP.equals(scheme) && LOOPBACK_HOSTS.contains(host)) {
      return;
    }
    throw new IllegalArgumentException(
        "endpoint must use https (plain http is allowed for loopback hosts only): "
            + scheme + "://" + host);
  }

  private static void requireCleanHeader(String name, String value) {
    if (name == null || name.isBlank() || containsControlCharacter(name)) {
      throw new IllegalArgumentException("invalid static header name");
    }
    if (value == null || containsControlCharacter(value)) {
      // CWE-93: never echo the value — it may be a credential.
      throw new IllegalArgumentException(
          "static header '" + name + "' carries a control character in its value");
    }
  }

  static boolean containsControlCharacter(String value) {
    for (int i = 0; i < value.length(); i++) {
      char c = value.charAt(i);
      if (c < 0x20 || c == 0x7F) {
        return true;
      }
    }
    return false;
  }

  private static void requirePositive(Duration duration, String name) {
    if (duration.isZero() || duration.isNegative()) {
      throw new IllegalArgumentException(name + " must be positive");
    }
  }
}
