package eu.jsentinel.jcustos.events.webhook;

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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("WebhookPublisherConfig — wiring-time validation")
class WebhookPublisherConfigTest {

  private static final URI HTTPS = URI.create("https://hooks.example.com/security");

  @Test
  @DisplayName("https endpoints are accepted for any host")
  void httpsAccepted() {
    assertDoesNotThrow(() -> WebhookPublisherConfig.defaults(HTTPS));
  }

  @Test
  @DisplayName("plain http is accepted for loopback hosts only")
  void httpLoopbackOnly() {
    assertDoesNotThrow(() ->
        WebhookPublisherConfig.defaults(URI.create("http://localhost:8080/hook")));
    assertDoesNotThrow(() ->
        WebhookPublisherConfig.defaults(URI.create("http://127.0.0.1:8080/hook")));
    assertThrows(IllegalArgumentException.class, () ->
        WebhookPublisherConfig.defaults(URI.create("http://hooks.example.com/hook")));
  }

  @Test
  @DisplayName("a control character in a static header value is rejected naming the header name only")
  void headerInjectionGuard() {
    IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () ->
        new WebhookPublisherConfig(HTTPS,
            Duration.ofSeconds(1), Duration.ofSeconds(1), 8, 1,
            Duration.ofMillis(10), Duration.ofMillis(10),
            Map.of("X-Secret", "top\r\nInjected: header"),
            Optional::empty));
    assertTrue(ex.getMessage().contains("X-Secret"));
    // CWE-93: the value may be a credential — it must not be echoed.
    assertFalse(ex.getMessage().contains("Injected"));
  }

  @Test
  @DisplayName("blank header names and control characters in names are rejected")
  void headerNameGuard() {
    assertThrows(IllegalArgumentException.class, () ->
        new WebhookPublisherConfig(HTTPS,
            Duration.ofSeconds(1), Duration.ofSeconds(1), 8, 1,
            Duration.ofMillis(10), Duration.ofMillis(10),
            Map.of(" ", "value"),
            Optional::empty));
  }

  @Test
  @DisplayName("capacity, attempts and backoff bounds are validated")
  void numericGuards() {
    assertThrows(IllegalArgumentException.class, () -> config(0, 1,
        Duration.ofMillis(10), Duration.ofMillis(10)));
    assertThrows(IllegalArgumentException.class, () -> config(8, 0,
        Duration.ofMillis(10), Duration.ofMillis(10)));
    assertThrows(IllegalArgumentException.class, () -> config(8, 1,
        Duration.ZERO, Duration.ofMillis(10)));
    assertThrows(IllegalArgumentException.class, () -> config(8, 1,
        Duration.ofMillis(20), Duration.ofMillis(10)));
  }

  @Test
  @DisplayName("defaults() carries the documented production-lean values")
  void defaultsPinned() {
    WebhookPublisherConfig config = WebhookPublisherConfig.defaults(HTTPS);
    assertEquals(Duration.ofSeconds(5), config.connectTimeout());
    assertEquals(Duration.ofSeconds(10), config.requestTimeout());
    assertEquals(1024, config.queueCapacity());
    assertEquals(5, config.maxAttempts());
    assertEquals(Duration.ofMillis(500), config.initialBackoff());
    assertEquals(Duration.ofSeconds(30), config.maxBackoff());
    assertTrue(config.staticHeaders().isEmpty());
    assertEquals(Optional.empty(), config.bearerTokenSupplier().get());
  }

  @Test
  @DisplayName("the static-header map is defensively copied")
  void headersImmutable() {
    WebhookPublisherConfig config = WebhookPublisherConfig.defaults(HTTPS);
    assertThrows(UnsupportedOperationException.class,
        () -> config.staticHeaders().put("X-Late", "nope"));
  }

  private static WebhookPublisherConfig config(int capacity, int attempts,
      Duration initialBackoff, Duration maxBackoff) {
    return new WebhookPublisherConfig(HTTPS,
        Duration.ofSeconds(1), Duration.ofSeconds(1), capacity, attempts,
        initialBackoff, maxBackoff, Map.of(), Optional::empty);
  }
}
