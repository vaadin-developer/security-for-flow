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

import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.rest.RestSubjectResolver;
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
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

@DisplayName("SseStreamHttpHandler — disconnect handling")
class SseStreamHttpHandlerTest {

  @Test
  @DisplayName("R042: a write failure (client disconnect) removes the subscription, leaving no zombie")
  void disconnectRemovesSubscription() {
    assertTimeoutPreemptively(java.time.Duration.ofSeconds(5), () -> {
      SseEventBroadcaster broadcaster = new SseEventBroadcaster(new EnvelopeWireCodec());
      // keepAliveSeconds=0 → streamLive writes a keep-alive on the first idle
      // poll; the throwing OutputStream makes that first write fail, simulating
      // a client that has gone away. No envelope store → no replay.
      RestSubjectResolver authorized = req -> Optional.of(new JSentinelSubject(
          "u", "U", Set.of(), Set.of(new PermissionName(EventsRestRoutes.STREAM_PERMISSION))));
      SseStreamHttpHandler handler = new SseStreamHttpHandler(
          broadcaster, null, new EnvelopeWireCodec(), authorized,
          EventsRestRoutes.STREAM_PERMISSION, 0L, 100);

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
        EventsRestRoutes.STREAM_PERMISSION, 0L, 100);

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
        EventsRestRoutes.STREAM_PERMISSION, 0L, 100);

    CapturingExchange ex = new CapturingExchange();
    handler.handle(ex);

    assertEquals(403, ex.status);
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
    @Override public OutputStream getResponseBody() { return new ByteArrayOutputStream(); }
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
