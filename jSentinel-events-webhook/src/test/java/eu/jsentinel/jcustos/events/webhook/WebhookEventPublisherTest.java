package eu.jsentinel.jcustos.events.webhook;

/*-
 * #%L
 * jCustos Events — Webhook exporter
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpServer;
import eu.jsentinel.jcustos.events.api.SignedJCustosEventEnvelope;
import eu.jsentinel.jcustos.events.testkit.TestkitEnvelopes;
import eu.jsentinel.jcustos.events.wire.EnvelopeWireCodec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("WebhookEventPublisher — delivery over a real JDK HttpServer")
class WebhookEventPublisherTest {

  private record ReceivedRequest(byte[] body, Headers headers) {
  }

  private HttpServer server;
  private final ConcurrentLinkedQueue<ReceivedRequest> received = new ConcurrentLinkedQueue<>();
  private final AtomicInteger requestCount = new AtomicInteger();
  private final AtomicInteger failFirstN = new AtomicInteger();
  private volatile CountDownLatch handlerGate;
  private WebhookEventPublisher publisher;

  @BeforeEach
  void startServer() throws Exception {
    handlerGate = new CountDownLatch(0);
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/hook", exchange -> {
      try {
        handlerGate.await();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      byte[] body;
      try (InputStream in = exchange.getRequestBody()) {
        body = in.readAllBytes();
      }
      received.add(new ReceivedRequest(body, exchange.getRequestHeaders()));
      int n = requestCount.incrementAndGet();
      int status = n <= failFirstN.get() ? 500 : 200;
      exchange.sendResponseHeaders(status, -1);
      exchange.close();
    });
    server.start();
  }

  @AfterEach
  void stopServer() {
    if (publisher != null) {
      publisher.close();
    }
    server.stop(0);
  }

  @Test
  @DisplayName("round-trip: the body is the wire form, routing + auth headers are set")
  void roundTripDeliversWireFormAndHeaders() {
    publisher = publisher(config(8, 3, () -> Optional.of("token-123")), null);
    SignedJCustosEventEnvelope envelope = TestkitEnvelopes.envelope("env-rt");

    publisher.onEnvelope(envelope);

    await(() -> publisher.deliveredCount() == 1, "delivery");
    ReceivedRequest request = received.poll();
    SignedJCustosEventEnvelope decoded = new EnvelopeWireCodec()
        .decode(new String(request.body(), java.nio.charset.StandardCharsets.UTF_8))
        .getOrThrow();
    assertEquals(envelope, decoded,
        "the webhook body must round-trip through the shared wire codec");
    assertTrue(request.headers().getFirst("Content-Type").startsWith("application/json"));
    assertEquals(envelope.eventType().value(),
        request.headers().getFirst(WebhookEventPublisher.HEADER_EVENT_TYPE));
    assertEquals("env-rt",
        request.headers().getFirst(WebhookEventPublisher.HEADER_ENVELOPE_ID));
    assertEquals("Bearer token-123", request.headers().getFirst("Authorization"));
  }

  @Test
  @DisplayName("without a token supplier value no Authorization header is sent")
  void noTokenMeansNoAuthorizationHeader() {
    publisher = publisher(config(8, 3, Optional::empty), null);

    publisher.onEnvelope(TestkitEnvelopes.envelope("env-noauth"));

    await(() -> publisher.deliveredCount() == 1, "delivery");
    assertNull(received.poll().headers().getFirst("Authorization"));
  }

  @Test
  @DisplayName("retries with backoff until the endpoint recovers")
  void retriesUntilSuccess() {
    failFirstN.set(2);
    publisher = publisher(config(8, 5, Optional::empty), null);

    publisher.onEnvelope(TestkitEnvelopes.envelope("env-retry"));

    await(() -> publisher.deliveredCount() == 1, "delivery after retries");
    assertEquals(3, requestCount.get(), "two failures + one success");
    assertEquals(0, publisher.deadDroppedCount());
  }

  @Test
  @DisplayName("dead-drops after maxAttempts and the worker survives for later envelopes")
  void deadDropsAfterMaxAttemptsAndWorkerSurvives() {
    failFirstN.set(Integer.MAX_VALUE);
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    publisher = publisher(config(8, 3, Optional::empty), logger);

    publisher.onEnvelope(TestkitEnvelopes.envelope("env-dead"));

    await(() -> publisher.deadDroppedCount() == 1, "dead-drop");
    assertEquals(3, requestCount.get(), "exactly maxAttempts requests");
    assertTrue(logger.messages().stream()
            .anyMatch(m -> m.contains("events-webhook/delivery-dead-dropped")
                && m.contains("env-dead") && m.contains("status 500")),
        "dead-drop WARN carries envelope id + last status only");

    failFirstN.set(requestCount.get());
    publisher.onEnvelope(TestkitEnvelopes.envelope("env-after"));
    await(() -> publisher.deliveredCount() == 1, "worker survives a dead-drop");
  }

  @Test
  @DisplayName("a full queue drops without blocking the publish thread")
  void fullQueueDropsWithoutBlocking() throws Exception {
    handlerGate = new CountDownLatch(1);
    RecordingSlf4jLogger logger = new RecordingSlf4jLogger();
    publisher = publisher(config(1, 1, Optional::empty), logger);

    long start = System.nanoTime();
    for (int i = 0; i < 50; i++) {
      publisher.onEnvelope(TestkitEnvelopes.envelope("env-burst-" + i));
    }
    long elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);

    assertTrue(elapsedMillis < 1_000,
        "50 offers took " + elapsedMillis + " ms — onEnvelope must never block");
    assertTrue(publisher.droppedEnvelopeCount() > 0);
    assertTrue(logger.messages().stream()
            .anyMatch(m -> m.contains("events-webhook/enqueue-drop")),
        "the first drop is warned");
    handlerGate.countDown();
  }

  @Test
  @DisplayName("close is idempotent and counts still-queued envelopes as dropped")
  void closeIsIdempotentAndCountsQueued() {
    handlerGate = new CountDownLatch(1);
    publisher = publisher(config(8, 1, Optional::empty), null);

    for (int i = 0; i < 4; i++) {
      publisher.onEnvelope(TestkitEnvelopes.envelope("env-close-" + i));
    }
    publisher.close();
    long droppedAfterFirstClose = publisher.droppedEnvelopeCount();
    assertTrue(droppedAfterFirstClose >= 3,
        "the envelopes still queued at close are accounted as dropped");
    publisher.close();
    assertEquals(droppedAfterFirstClose, publisher.droppedEnvelopeCount(),
        "a second close must not double-count");
    handlerGate.countDown();

    publisher.onEnvelope(TestkitEnvelopes.envelope("env-post-close"));
    assertEquals(droppedAfterFirstClose + 1, publisher.droppedEnvelopeCount(),
        "post-close delivery is a counted silent drop");
    assertFalse(publisher.deliveredCount() > 0);
  }

  private WebhookEventPublisher publisher(WebhookPublisherConfig config,
      RecordingSlf4jLogger logger) {
    HttpClient client = HttpClient.newBuilder()
        .connectTimeout(config.connectTimeout())
        .followRedirects(HttpClient.Redirect.NEVER)
        .build();
    return new WebhookEventPublisher(config, client,
        logger == null ? new RecordingSlf4jLogger() : logger);
  }

  private WebhookPublisherConfig config(int capacity, int attempts,
      Supplier<Optional<String>> tokenSupplier) {
    return new WebhookPublisherConfig(
        URI.create("http://127.0.0.1:" + server.getAddress().getPort() + "/hook"),
        Duration.ofSeconds(2), Duration.ofSeconds(2), capacity, attempts,
        Duration.ofMillis(10), Duration.ofMillis(40),
        Map.of(), tokenSupplier);
  }

  private static void await(BooleanSupplier condition, String what) {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (!condition.getAsBoolean()) {
      if (System.nanoTime() > deadline) {
        throw new AssertionError("timed out waiting for " + what);
      }
      try {
        Thread.sleep(10);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AssertionError("interrupted waiting for " + what, e);
      }
    }
  }
}
