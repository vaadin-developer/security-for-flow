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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.dependencies.core.net.MediaType;
import com.svenruppert.jsentinel.audit.LogFieldScrubber;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.SignedJSentinelEventEnvelope;
import com.svenruppert.jsentinel.events.publisher.SignedEnvelopePublisher;
import com.svenruppert.jsentinel.events.wire.EnvelopeWireCodec;
import org.slf4j.Logger;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

import static com.svenruppert.dependencies.core.net.HttpStatus.fromCode;

/**
 * {@link SignedEnvelopePublisher} that delivers every published envelope to
 * an outbound webhook over the JDK {@link HttpClient}. Konzept goal 8
 * (V00.80.00): signed envelopes are the integration base — the request body
 * is the {@link EnvelopeWireCodec} wire form, byte-identical to the REST/SSE
 * bridge, so a receiver can feed it straight into its own verification
 * pipeline.
 * <p>
 * Delivery model: {@link #onEnvelope(SignedJSentinelEventEnvelope)} only
 * enqueues into a bounded in-memory queue and NEVER blocks the publish
 * thread; a single dedicated virtual-thread worker drains the queue (one
 * worker keeps per-target envelope order). A full queue drops the envelope
 * (counted, rate-limited WARN). Delivery retries with exponential backoff
 * plus jitter up to {@code maxAttempts}, then dead-drops the envelope
 * (counted, WARN with the envelope id and the last status only — never the
 * response body, never response headers, never the bearer token).
 * <p>
 * <strong>No second HMAC layer by design:</strong> the envelope body is
 * already asymmetrically signed over payload and security metadata, and
 * receivers verify it via the events verification SPIs. A transport-level
 * HMAC header would add a weaker shared-secret channel duplicating those
 * guarantees.
 * <p>
 * Redirects are disabled ({@link HttpClient.Redirect#NEVER}): following one
 * could re-send the {@code Authorization} header to an unexpected host.
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class WebhookEventPublisher
    implements SignedEnvelopePublisher, HasLogger, AutoCloseable {

  /** Routing header carrying the envelope's event type. */
  public static final String HEADER_EVENT_TYPE = "X-JSentinel-Event-Type";
  /** Routing header carrying the envelope id. */
  public static final String HEADER_ENVELOPE_ID = "X-JSentinel-Envelope-Id";

  private static final String HEADER_CONTENT_TYPE = "Content-Type";
  private static final String HEADER_AUTHORIZATION = "Authorization";
  private static final String BEARER_PREFIX = "Bearer ";
  /** Mirrors the drop-log policy of the SSE broadcaster (R041). */
  private static final int DROP_LOG_INTERVAL = 100;
  private static final Duration CLOSE_JOIN_TIMEOUT = Duration.ofSeconds(5);
  private static final String WORKER_THREAD_NAME = "jsentinel-webhook-delivery";
  private static final double JITTER_RATIO = 0.2;

  private final WebhookPublisherConfig config;
  private final HttpClient client;
  private final Logger logger;
  private final EnvelopeWireCodec codec = new EnvelopeWireCodec();
  private final BlockingQueue<SignedJSentinelEventEnvelope> queue;
  private final Thread worker;
  private final AtomicBoolean closed = new AtomicBoolean();
  private final AtomicLong delivered = new AtomicLong();
  private final AtomicLong dropped = new AtomicLong();
  private final AtomicLong deadDropped = new AtomicLong();
  private final AtomicLong retryLogged = new AtomicLong();

  public WebhookEventPublisher(WebhookPublisherConfig config) {
    this(config,
        HttpClient.newBuilder()
            .connectTimeout(Objects.requireNonNull(config, "config").connectTimeout())
            .followRedirects(HttpClient.Redirect.NEVER)
            .build(),
        HasLogger.staticLogger());
  }

  /**
   * Test / injection seam mirroring the {@code LoggingAuditSink} pattern:
   * lets tests supply a prebuilt client and pin the WARN lines through a
   * recording logger.
   */
  WebhookEventPublisher(WebhookPublisherConfig config, HttpClient client, Logger logger) {
    this.config = Objects.requireNonNull(config, "config");
    this.client = Objects.requireNonNull(client, "client");
    this.logger = Objects.requireNonNull(logger, "logger");
    this.queue = new ArrayBlockingQueue<>(config.queueCapacity());
    this.worker = Thread.ofVirtual().name(WORKER_THREAD_NAME).start(this::drainLoop);
  }

  @Override
  public Logger logger() {
    return logger;
  }

  @Override
  public void onEnvelope(SignedJSentinelEventEnvelope envelope) {
    if (envelope == null || closed.get()) {
      if (envelope != null) {
        dropped.incrementAndGet();
      }
      return;
    }
    if (!queue.offer(envelope)) {
      long total = dropped.incrementAndGet();
      if (total % DROP_LOG_INTERVAL == 1) {
        logger().warn(
            "events-webhook/enqueue-drop: delivery queue full, dropped envelope {} "
                + "(total dropped={})",
            LogFieldScrubber.scrub(envelope.envelopeId().value()), total);
      }
      return;
    }
    // RF00: close() may have drained the queue between the closed check
    // above and the offer — reclaim the stranded envelope so the drop
    // accounting stays exact.
    if (closed.get() && queue.remove(envelope)) {
      dropped.incrementAndGet();
    }
  }

  /** @return envelopes acknowledged with a 2xx response */
  public long deliveredCount() {
    return delivered.get();
  }

  /** @return envelopes dropped before delivery (full queue, post-close, shutdown drain) */
  public long droppedEnvelopeCount() {
    return dropped.get();
  }

  /** @return envelopes given up on after {@code maxAttempts} failed deliveries */
  public long deadDroppedCount() {
    return deadDropped.get();
  }

  /** @return envelopes currently waiting for delivery */
  public int queueDepth() {
    return queue.size();
  }

  /**
   * Idempotent: stops the worker (bounded {@value}-second join), counts the
   * envelopes still queued as dropped. Post-close deliveries are silent
   * drops (counted).
   */
  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) {
      return;
    }
    worker.interrupt();
    try {
      worker.join(CLOSE_JOIN_TIMEOUT);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
    int remaining = queue.size();
    if (remaining > 0) {
      queue.clear();
      dropped.addAndGet(remaining);
    }
  }

  private void drainLoop() {
    while (!closed.get()) {
      SignedJSentinelEventEnvelope envelope;
      try {
        envelope = queue.take();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        return;
      }
      deliverWithRetry(envelope);
    }
  }

  private void deliverWithRetry(SignedJSentinelEventEnvelope envelope) {
    String scrubbedId = LogFieldScrubber.scrub(envelope.envelopeId().value());
    if (WebhookPublisherConfig.containsControlCharacter(envelope.eventType().value())
        || WebhookPublisherConfig.containsControlCharacter(envelope.envelopeId().value())) {
      // CWE-93 belt-and-suspenders: the ids are envelope-validated, but a
      // control character here would corrupt the routing headers — refuse
      // to send rather than risk header splitting.
      deadDropped.incrementAndGet();
      logger().warn(
          "events-webhook/invalid-header-value: envelope {} not sent — its event type "
              + "or id carries a control character",
          scrubbedId);
      return;
    }
    String body = codec.encode(envelope);
    String lastFailure = "";
    for (int attempt = 1; attempt <= config.maxAttempts(); attempt++) {
      if (closed.get()) {
        dropped.incrementAndGet();
        return;
      }
      try {
        HttpResponse<Void> response = client.send(
            request(envelope, body), HttpResponse.BodyHandlers.discarding());
        if (fromCode(response.statusCode()).isSuccessful()) {
          delivered.incrementAndGet();
          return;
        }
        lastFailure = "status " + response.statusCode();
      } catch (IOException e) {
        // Never the message: an exception text may echo URLs or peer data.
        lastFailure = e.getClass().getSimpleName();
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        dropped.incrementAndGet();
        return;
      }
      if (attempt < config.maxAttempts()) {
        long logged = retryLogged.incrementAndGet();
        if (logged % DROP_LOG_INTERVAL == 1) {
          logger().warn(
              "events-webhook/delivery-retry: envelope {} attempt {}/{} failed ({})",
              scrubbedId, attempt, config.maxAttempts(), lastFailure);
        }
        if (!sleepBackoff(attempt)) {
          dropped.incrementAndGet();
          return;
        }
      }
    }
    deadDropped.incrementAndGet();
    logger().warn(
        "events-webhook/delivery-dead-dropped: envelope {} gave up after {} attempts ({})",
        scrubbedId, config.maxAttempts(), lastFailure);
  }

  private HttpRequest request(SignedJSentinelEventEnvelope envelope, String body) {
    HttpRequest.Builder builder = HttpRequest.newBuilder(config.endpoint())
        .timeout(config.requestTimeout())
        .header(HEADER_CONTENT_TYPE, MediaType.APPLICATION_JSON.withCharsetUtf8())
        .header(HEADER_EVENT_TYPE, envelope.eventType().value())
        .header(HEADER_ENVELOPE_ID, envelope.envelopeId().value());
    config.staticHeaders().forEach(builder::header);
    // Resolved freshly per attempt so rotated tokens take effect mid-retry;
    // the token itself never reaches any log or exception text.
    Optional<String> token = config.bearerTokenSupplier().get();
    token.ifPresent(t -> builder.header(HEADER_AUTHORIZATION, BEARER_PREFIX + t));
    return builder
        .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
        .build();
  }

  /**
   * Exponential backoff with +/-20 % jitter, capped at
   * {@code maxBackoff}. The jitter is intentionally non-deterministic —
   * tests must not pin exact delays.
   *
   * @return {@code false} when interrupted (worker is shutting down)
   */
  private boolean sleepBackoff(int completedAttempt) {
    long base = config.initialBackoff().toMillis();
    long capped = Math.min(
        base << Math.min(completedAttempt - 1, 20),
        config.maxBackoff().toMillis());
    double jitter = 1.0 + (ThreadLocalRandom.current().nextDouble() * 2 - 1) * JITTER_RATIO;
    long delay = Math.max(1L, (long) (capped * jitter));
    try {
      Thread.sleep(delay);
      return true;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return false;
    }
  }
}
