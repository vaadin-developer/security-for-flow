package eu.jsentinel.jcustos.events.rest;

/*-
 * #%L
 * jSentinel Events — REST / SSE bridge
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
import com.svenruppert.dependencies.core.net.HttpStatus;
import eu.jsentinel.jcustos.audit.LogFieldScrubber;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionMatcher;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.events.store.JSentinelEventCursor;
import eu.jsentinel.jcustos.events.store.JSentinelEventEnvelopeStore;
import eu.jsentinel.jcustos.events.store.StoredEnvelope;
import eu.jsentinel.jcustos.events.wire.EnvelopeWireCodec;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.TimeUnit;

/**
 * JDK-{@code HttpServer} SSE endpoint for {@code GET /api/events/stream}
 * (Konzept §929-§968). On connect it replays any envelopes after the
 * {@code Last-Event-ID} cursor from the envelope store, then live-tails new
 * envelopes from the {@link SseEventBroadcaster}, emitting a keep-alive comment
 * whenever the stream is idle. Drops to the raw {@link HttpExchange} stream
 * because jSentinel-rest's buffered {@code RestResponse} cannot stream.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class SseStreamHttpHandler implements HttpHandler, HasLogger {

  /** JS-SEC-032 (CWE-306): cap on the auth-probe read of the (bodyless) GET request. */
  private static final int MAX_AUTH_PROBE_BODY_BYTES = 8 * 1024;

  /** JS-SEC-049 (CWE-400): default cap on concurrent SSE streams (each pins one server thread). */
  public static final int DEFAULT_MAX_SUBSCRIBERS = 256;

  private final SseEventBroadcaster broadcaster;
  private final JSentinelEventEnvelopeStore envelopeStore;
  private final EnvelopeWireCodec wireCodec;
  private final RestSubjectResolver subjectResolver;
  private final PermissionName requiredPermission;
  private final long keepAliveSeconds;
  private final int replayBatch;
  private final int maxSubscribers;
  private final java.util.concurrent.atomic.AtomicInteger activeStreams =
      new java.util.concurrent.atomic.AtomicInteger();

  public SseStreamHttpHandler(SseEventBroadcaster broadcaster,
      JSentinelEventEnvelopeStore envelopeStore, EnvelopeWireCodec wireCodec,
      RestSubjectResolver subjectResolver, String requiredPermission,
      long keepAliveSeconds, int replayBatch) {
    this(broadcaster, envelopeStore, wireCodec, subjectResolver, requiredPermission,
        keepAliveSeconds, replayBatch, DEFAULT_MAX_SUBSCRIBERS);
  }

  /**
   * JS-SEC-049 (CWE-400): {@code maxSubscribers} bounds the number of concurrent streams. Each SSE
   * connection pins one blocking JDK-HttpServer thread for its lifetime (a connected-but-non-reading
   * client blocks the write indefinitely), so without a cap an authenticated {@code events:subscribe}
   * holder could open many streams and starve every other endpoint on the same server. Size the
   * server's executor with a bound accounting for this cap, and consider setting the JDK
   * {@code sun.net.httpserver.maxRspTime} for a write deadline.
   */
  public SseStreamHttpHandler(SseEventBroadcaster broadcaster,
      JSentinelEventEnvelopeStore envelopeStore, EnvelopeWireCodec wireCodec,
      RestSubjectResolver subjectResolver, String requiredPermission,
      long keepAliveSeconds, int replayBatch, int maxSubscribers) {
    this.broadcaster = Objects.requireNonNull(broadcaster, "broadcaster");
    this.envelopeStore = envelopeStore; // optional (resume disabled when null)
    this.wireCodec = Objects.requireNonNull(wireCodec, "wireCodec");
    this.subjectResolver = Objects.requireNonNull(subjectResolver, "subjectResolver");
    this.requiredPermission = new PermissionName(
        Objects.requireNonNull(requiredPermission, "requiredPermission"));
    // R08 (CWE-400): keepAliveSeconds <= 0 would busy-spin streamLive() (poll(0) is a tight
    // loop writing keep-alive frames), and replayBatch <= 0 would reach findAfter(...) as an
    // invalid page size — reject both at construction, symmetric with maxSubscribers below.
    if (keepAliveSeconds < 1) {
      throw new IllegalArgumentException("keepAliveSeconds must be >= 1");
    }
    this.keepAliveSeconds = keepAliveSeconds;
    if (replayBatch < 1) {
      throw new IllegalArgumentException("replayBatch must be >= 1");
    }
    this.replayBatch = replayBatch;
    if (maxSubscribers < 1) {
      throw new IllegalArgumentException("maxSubscribers must be >= 1");
    }
    this.maxSubscribers = maxSubscribers;
  }

  /** @return the number of currently-open SSE streams (JS-SEC-049 — operators can alarm on this). */
  public int activeStreamCount() {
    return activeStreams.get();
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
      writeStatus(exchange, HttpStatus.METHOD_NOT_ALLOWED.code());
      return;
    }
    // JS-SEC-032 (CWE-306): the read side self-authorizes symmetrically with the publish
    // sibling — resolve the subject and require the permission BEFORE opening the stream
    // (before the 200 and before any replay), so an unauthenticated client cannot harvest
    // the security-event feed.
    HttpExchangeRestRequest authProbe;
    try {
      authProbe = HttpExchangeRestRequest.read(exchange, MAX_AUTH_PROBE_BODY_BYTES);
    } catch (RequestBodyTooLargeException tooLarge) {
      writeStatus(exchange, HttpStatus.CONTENT_TOO_LARGE.code());
      return;
    } catch (UncheckedIOException e) {
      writeStatus(exchange, HttpStatus.BAD_REQUEST.code());
      return;
    }
    Optional<JSentinelSubject> subject = subjectResolver.resolveSubject(authProbe);
    if (subject.isEmpty()) {
      writeStatus(exchange, HttpStatus.UNAUTHORIZED.code());
      return;
    }
    // RF (exit-review): match the framework's evaluator path (RequiresPermissionEvaluator
    // uses PermissionMatcher), which honors terminal-wildcard grants such as "events:*".
    // A flat permissions().contains(...) is exact-match only, so a subject holding
    // "events:*" (or an admin granted events:subscribe via a wildcard) would be denied
    // here while passing @RequiresPermission("events:subscribe") on regular handlers.
    if (!PermissionMatcher.containsAll(
        subject.get().permissionNames(), Set.of(requiredPermission))) {
      writeStatus(exchange, HttpStatus.FORBIDDEN.code());
      return;
    }
    // JS-SEC-049 (CWE-400): atomically reserve a stream slot BEFORE the 200 + stream. Each stream
    // pins one server thread for its lifetime, so a full pool is refused with 503 + Retry-After
    // rather than opening a stream that would starve other endpoints. The slot is released on every
    // exit path in the finally below.
    if (activeStreams.incrementAndGet() > maxSubscribers) {
      activeStreams.decrementAndGet();
      exchange.getResponseHeaders().add("Retry-After", "5");
      writeStatus(exchange, HttpStatus.SERVICE_UNAVAILABLE.code());
      return;
    }
    try {
      exchange.getResponseHeaders().add("Content-Type", EventsRestRoutes.EVENT_STREAM_MEDIA_TYPE);
      exchange.getResponseHeaders().add("Cache-Control", "no-cache");
      exchange.getResponseHeaders().add("Connection", "keep-alive");
      exchange.sendResponseHeaders(HttpStatus.OK.code(), 0);

      BoundedQueueSseSubscriber subscriber = new BoundedQueueSseSubscriber();
      // R042: the broadcaster registration is an AutoCloseable held by this
      // try-with-resources, so the subscriber is removed on EVERY exit path —
      // normal completion, client disconnect (IOException from write), interrupt
      // or any other error — leaving no zombie subscription. The keep-alive write
      // in streamLive() bounds detection latency to keepAliveSeconds even when no
      // real events flow.
      try (OutputStream out = exchange.getResponseBody();
           AutoCloseable registration = broadcaster.register(subscriber)) {
        replaySince(resumeCursor(exchange), out);
        streamLive(subscriber, out);
      } catch (IOException disconnected) {
        // R07 (CWE-117): exception texts on these two paths can carry client-influenced or
        // envelope-derived content — scrub before logging, matching the publish sibling's
        // JS-SEC-054 treatment of unexpected.toString().
        logger().info("events-rest/sse-disconnect: {}",
            LogFieldScrubber.scrub(disconnected.toString()));
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      } catch (Exception e) {
        logger().warn("events-rest/sse-error: {}", LogFieldScrubber.scrub(e.toString()));
      } finally {
        exchange.close();
      }
    } finally {
      activeStreams.decrementAndGet();
    }
  }

  private JSentinelEventCursor resumeCursor(HttpExchange exchange) {
    List<String> header = exchange.getRequestHeaders().get("Last-Event-ID");
    if (header == null || header.isEmpty()) {
      return JSentinelEventCursor.start();
    }
    try {
      return JSentinelEventCursor.at(Long.parseLong(header.get(0).trim()));
    } catch (IllegalArgumentException invalid) {
      // R05: a malformed value (NumberFormatException) and a negative position (the
      // cursor's own IllegalArgumentException) both degrade to a full replay from the
      // start — a client-supplied "-1" must behave exactly like a missing header
      // instead of aborting the stream.
      return JSentinelEventCursor.start();
    }
  }

  private void replaySince(JSentinelEventCursor cursor, OutputStream out) throws IOException {
    if (envelopeStore == null) {
      return;
    }
    JSentinelEventCursor position = cursor;
    while (true) {
      List<StoredEnvelope> page = envelopeStore.findAfter(position, replayBatch);
      if (page.isEmpty()) {
        return;
      }
      for (StoredEnvelope stored : page) {
        write(out, SseFrames.securityEvent(
            stored.cursor().position(), wireCodec.encode(stored.envelope())));
        position = stored.cursor();
      }
    }
  }

  private void streamLive(BoundedQueueSseSubscriber subscriber, OutputStream out)
      throws IOException, InterruptedException {
    while (!Thread.currentThread().isInterrupted()) {
      String frame = subscriber.poll(keepAliveSeconds, TimeUnit.SECONDS);
      write(out, frame != null ? frame : SseFrames.keepAlive());
    }
  }

  private static void write(OutputStream out, String frame) throws IOException {
    out.write(frame.getBytes(StandardCharsets.UTF_8));
    out.flush();
  }

  private static void writeStatus(HttpExchange exchange, int status) throws IOException {
    exchange.sendResponseHeaders(status, -1);
    exchange.close();
  }
}
