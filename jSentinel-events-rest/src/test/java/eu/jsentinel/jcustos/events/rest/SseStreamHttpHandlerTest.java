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

import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import eu.jsentinel.jcustos.events.wire.EnvelopeWireCodec;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

@DisplayName("SseStreamHttpHandler")
class SseStreamHttpHandlerTest {

  @Test
  @DisplayName("R042: a write failure (client disconnect) removes the subscription, leaving no zombie")
  void disconnectRemovesSubscription() {
    assertTimeoutPreemptively(java.time.Duration.ofSeconds(5), () -> {
      SseEventBroadcaster broadcaster = new SseEventBroadcaster(new EnvelopeWireCodec());
      // keepAliveSeconds=1 → streamLive writes a keep-alive after the first idle
      // poll; the throwing OutputStream makes that first write fail, simulating
      // a client that has gone away. No envelope store → no replay.
      RestSubjectResolver authorized = req -> Optional.of(new JSentinelSubject(
          "u", "U", Set.of(), Set.of(new PermissionName(EventsRestRoutes.STREAM_PERMISSION))));
      SseStreamHttpHandler handler = new SseStreamHttpHandler(
          broadcaster, null, new EnvelopeWireCodec(), authorized,
          EventsRestRoutes.STREAM_PERMISSION, 1L, 100);

      handler.handle(new DisconnectedExchange());

      assertEquals(0, broadcaster.subscriberCount(),
          "a write failure must unregister the subscriber (no zombie subscription)");
    });
  }

  @Test
  @DisplayName("JS-SEC-032: an unauthenticated GET /stream is rejected 401 before any replay/stream")
  void unauthenticatedStreamRejected() throws IOException {
    SseEventBroadcaster broadcaster = new SseEventBroadcaster(new EnvelopeWireCodec());
    RestSubjectResolver noSubject = req -> Optional.empty();
    SseStreamHttpHandler handler = new SseStreamHttpHandler(
        broadcaster, null, new EnvelopeWireCodec(), noSubject,
        EventsRestRoutes.STREAM_PERMISSION, 1L, 100);

    CapturingExchange ex = new CapturingExchange();
    handler.handle(ex);

    assertEquals(401, ex.status);
    assertEquals(0, broadcaster.subscriberCount(),
        "no subscription may be opened for an unauthenticated request");
  }

  @Test
  @DisplayName("JS-SEC-032: a subject lacking the stream permission is rejected 403")
  void insufficientPermissionStreamRejected() throws IOException {
    SseEventBroadcaster broadcaster = new SseEventBroadcaster(new EnvelopeWireCodec());
    RestSubjectResolver wrongPerm = req -> Optional.of(new JSentinelSubject(
        "u", "U", Set.of(), Set.of(new PermissionName(EventsRestRoutes.PUBLISH_PERMISSION))));
    SseStreamHttpHandler handler = new SseStreamHttpHandler(
        broadcaster, null, new EnvelopeWireCodec(), wrongPerm,
        EventsRestRoutes.STREAM_PERMISSION, 1L, 100);

    CapturingExchange ex = new CapturingExchange();
    handler.handle(ex);

    assertEquals(403, ex.status);
  }

  @Test
  @DisplayName("RF (exit-review): a subject holding a terminal-wildcard permission (events:*) may stream")
  void wildcardPermissionStreamAllowed() {
    assertTimeoutPreemptively(java.time.Duration.ofSeconds(5), () -> {
      SseEventBroadcaster broadcaster = new SseEventBroadcaster(new EnvelopeWireCodec());
      // "events:*" is not equal to "events:subscribe" but grants it via PermissionMatcher —
      // the same wildcard semantics @RequiresPermission uses. A flat contains() would 403 this.
      RestSubjectResolver wildcard = req -> Optional.of(new JSentinelSubject(
          "u", "U", Set.of(), Set.of(new PermissionName("events:*"))));
      SseStreamHttpHandler handler = new SseStreamHttpHandler(
          broadcaster, null, new EnvelopeWireCodec(), wildcard,
          EventsRestRoutes.STREAM_PERMISSION, 1L, 100);

      CapturingExchange ex = new CapturingExchange();
      handler.handle(ex);

      // auth passed → the stream opened with a 200 (the keep-alive write then fails on the
      // throwing body, terminating the handler). A 403 here would mean the wildcard was ignored.
      assertEquals(200, ex.status);
    });
  }

  @Test
  @DisplayName("JS-SEC-049: a full subscriber pool refuses a new stream with 503")
  void concurrentCapReturns503() {
    assertTimeoutPreemptively(java.time.Duration.ofSeconds(5), () -> {
      SseEventBroadcaster broadcaster = new SseEventBroadcaster(new EnvelopeWireCodec());
      RestSubjectResolver authorized = req -> Optional.of(new JSentinelSubject(
          "u", "U", Set.of(), Set.of(new PermissionName(EventsRestRoutes.STREAM_PERMISSION))));
      // keepAlive large so the first stream parks in poll() holding its slot; cap = 1.
      SseStreamHttpHandler handler = new SseStreamHttpHandler(
          broadcaster, null, new EnvelopeWireCodec(), authorized,
          EventsRestRoutes.STREAM_PERMISSION, 3600L, 100, 1);

      Thread first = new Thread(() -> {
        try {
          handler.handle(new CapturingExchange());
        } catch (Exception ignored) {
          // interrupted at teardown
        }
      });
      first.setDaemon(true);
      first.start();

      // wait until the first stream has reserved the only slot
      while (handler.activeStreamCount() < 1) {
        Thread.sleep(5);
      }

      CapturingExchange second = new CapturingExchange();
      handler.handle(second);
      assertEquals(503, second.status, "a full subscriber pool must refuse with 503");

      first.interrupt();
    });
  }

  @Test
  @DisplayName("R08: keepAliveSeconds < 1 is rejected at construction (poll(0) would busy-spin)")
  void keepAliveSecondsGuard() {
    assertThrows(IllegalArgumentException.class, () -> newHandler(0L, 100));
    assertThrows(IllegalArgumentException.class, () -> newHandler(-1L, 100));
  }

  @Test
  @DisplayName("R08: replayBatch < 1 is rejected at construction (invalid findAfter page size)")
  void replayBatchGuard() {
    assertThrows(IllegalArgumentException.class, () -> newHandler(1L, 0));
    assertThrows(IllegalArgumentException.class, () -> newHandler(1L, -1));
  }

  private static SseStreamHttpHandler newHandler(long keepAliveSeconds, int replayBatch) {
    return new SseStreamHttpHandler(
        new SseEventBroadcaster(new EnvelopeWireCodec()), null, new EnvelopeWireCodec(),
        req -> Optional.empty(), EventsRestRoutes.STREAM_PERMISSION,
        keepAliveSeconds, replayBatch);
  }

  /** Fake exchange whose response body throws on the first write (dead client). */
  private static final class DisconnectedExchange extends HttpExchange {
    private final Headers requestHeaders = new Headers();
    private final Headers responseHeaders = new Headers();

    @Override public Headers getRequestHeaders() { return requestHeaders; }
    @Override public Headers getResponseHeaders() { return responseHeaders; }
    @Override public URI getRequestURI() { return URI.create("/api/events/stream"); }
    @Override public String getRequestMethod() { return "GET"; }
    @Override public HttpContext getHttpContext() { return null; }
    @Override public void close() { /* no-op */ }
    @Override public InputStream getRequestBody() { return new ByteArrayInputStream(new byte[0]); }

    @Override public OutputStream getResponseBody() {
      return new OutputStream() {
        @Override public void write(int b) throws IOException {
          throw new IOException("client gone");
        }
        @Override public void write(byte[] b) throws IOException {
          throw new IOException("client gone");
        }
        @Override public void write(byte[] b, int off, int len) throws IOException {
          throw new IOException("client gone");
        }
      };
    }

    @Override public void sendResponseHeaders(int rCode, long responseLength) { /* no-op */ }
    @Override public InetSocketAddress getRemoteAddress() { return null; }
    @Override public int getResponseCode() { return 200; }
    @Override public InetSocketAddress getLocalAddress() { return null; }
    @Override public String getProtocol() { return "HTTP/1.1"; }
    @Override public Object getAttribute(String name) { return null; }
    @Override public void setAttribute(String name, Object value) { /* no-op */ }
    @Override public void setStreams(InputStream i, OutputStream o) { /* no-op */ }
    @Override public HttpPrincipal getPrincipal() { return null; }
  }

  /** Fake exchange capturing the response status; empty request body, discardable response. */
  private static final class CapturingExchange extends HttpExchange {
    private final Headers requestHeaders = new Headers();
    private final Headers responseHeaders = new Headers();
    int status = -1;

    @Override public Headers getRequestHeaders() { return requestHeaders; }
    @Override public Headers getResponseHeaders() { return responseHeaders; }
    @Override public URI getRequestURI() { return URI.create("/api/events/stream"); }
    @Override public String getRequestMethod() { return "GET"; }
    @Override public HttpContext getHttpContext() { return null; }
    @Override public void close() { /* no-op */ }
    @Override public InputStream getRequestBody() { return new ByteArrayInputStream(new byte[0]); }
    // Body write throws so an auth-PASS path (which opens the stream and writes a
    // keep-alive) terminates instead of blocking — the rejection paths return before
    // ever touching the body, so this does not affect them.
    @Override public OutputStream getResponseBody() {
      return new OutputStream() {
        @Override public void write(int b) throws IOException { throw new IOException("client gone"); }
        @Override public void write(byte[] b) throws IOException { throw new IOException("client gone"); }
        @Override public void write(byte[] b, int off, int len) throws IOException {
          throw new IOException("client gone");
        }
      };
    }
    @Override public void sendResponseHeaders(int rCode, long responseLength) { this.status = rCode; }
    @Override public InetSocketAddress getRemoteAddress() { return null; }
    @Override public int getResponseCode() { return status; }
    @Override public InetSocketAddress getLocalAddress() { return null; }
    @Override public String getProtocol() { return "HTTP/1.1"; }
    @Override public Object getAttribute(String name) { return null; }
    @Override public void setAttribute(String name, Object value) { /* no-op */ }
    @Override public void setStreams(InputStream i, OutputStream o) { /* no-op */ }
    @Override public HttpPrincipal getPrincipal() { return null; }
  }
}
