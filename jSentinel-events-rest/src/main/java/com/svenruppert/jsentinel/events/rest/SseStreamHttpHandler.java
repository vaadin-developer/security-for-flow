package com.svenruppert.jsentinel.events.rest;

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
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionMatcher;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.events.store.JSentinelEventCursor;
import com.svenruppert.jsentinel.events.store.JSentinelEventEnvelopeStore;
import com.svenruppert.jsentinel.events.store.StoredEnvelope;
import com.svenruppert.jsentinel.rest.RestSubjectResolver;
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

  private final SseEventBroadcaster broadcaster;
  private final JSentinelEventEnvelopeStore envelopeStore;
  private final EnvelopeWireCodec wireCodec;
  private final RestSubjectResolver subjectResolver;
  private final PermissionName requiredPermission;
  private final long keepAliveSeconds;
  private final int replayBatch;

  public SseStreamHttpHandler(SseEventBroadcaster broadcaster,
      JSentinelEventEnvelopeStore envelopeStore, EnvelopeWireCodec wireCodec,
      RestSubjectResolver subjectResolver, String requiredPermission,
      long keepAliveSeconds, int replayBatch) {
    this.broadcaster = Objects.requireNonNull(broadcaster, "broadcaster");
    this.envelopeStore = envelopeStore; // optional (resume disabled when null)
    this.wireCodec = Objects.requireNonNull(wireCodec, "wireCodec");
    this.subjectResolver = Objects.requireNonNull(subjectResolver, "subjectResolver");
    this.requiredPermission = new PermissionName(
        Objects.requireNonNull(requiredPermission, "requiredPermission"));
    this.keepAliveSeconds = keepAliveSeconds;
    this.replayBatch = replayBatch;
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
      logger().info("events-rest/sse-disconnect: {}", disconnected.toString());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (Exception e) {
      logger().warn("events-rest/sse-error: {}", e.toString());
    } finally {
      exchange.close();
    }
  }

  private JSentinelEventCursor resumeCursor(HttpExchange exchange) {
    List<String> header = exchange.getRequestHeaders().get("Last-Event-ID");
    if (header == null || header.isEmpty()) {
      return JSentinelEventCursor.start();
    }
    try {
      return JSentinelEventCursor.at(Long.parseLong(header.get(0).trim()));
    } catch (NumberFormatException e) {
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
