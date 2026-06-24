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

import com.svenruppert.dependencies.core.net.HttpStatus;
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
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;

@DisplayName("REST transport — query decoding + read-error mapping (H6)")
class HttpExchangeTransportTest {

  @Test
  @DisplayName("query parameters are URL-decoded (%XX, + as space, empty value)")
  void queryParametersAreUrlDecoded() {
    TestHttpExchange exchange = new TestHttpExchange()
        .withUri(URI.create("/api/events?a=hello%20world&b=a+b&c=&plus=%2B"));
    HttpExchangeRestRequest request = new HttpExchangeRestRequest(exchange, new byte[0]);

    Map<String, String> params = request.queryParameters();
    assertEquals("hello world", params.get("a"));   // %20 -> space
    assertEquals("a b", params.get("b"));            // + -> space
    assertEquals("", params.get("c"));               // empty value
    assertEquals("+", params.get("plus"));           // %2B -> literal +, not double-decoded
    // Note: a malformed escape (bare/incomplete %) cannot arrive here — URI
    // construction validates %-escapes first — so decode()'s IllegalArgumentException
    // fallback (RF01) is defensive only and is not separately constructible via URI.
  }

  @Test
  @DisplayName("a body-read failure maps to a clean 400, not a propagating UncheckedIOException")
  void readErrorMapsTo400() throws IOException {
    EventsRestFixtures fx = new EventsRestFixtures();
    EventPublishService publishService = new EventPublishService(
        new EnvelopeWireCodec(), fx.newConsumePipeline(), null, null,
        () -> EventsRestFixtures.T0);
    EventPublishHttpHandler handler = new EventPublishHttpHandler(
        publishService, request -> Optional.empty(), "events:publish");

    InputStream failing = new InputStream() {
      @Override public int read() throws IOException {
        throw new IOException("simulated client disconnect");
      }
      @Override public int read(byte[] b, int off, int len) throws IOException {
        throw new IOException("simulated client disconnect");
      }
    };
    TestHttpExchange exchange = new TestHttpExchange()
        .withMethod("POST")
        .withUri(URI.create("/api/events"))
        .withRequestBody(failing);

    handler.handle(exchange);

    assertEquals(HttpStatus.BAD_REQUEST.code(), exchange.responseStatus,
        "a read failure must surface as a clean 400");
  }

  /**
   * Hand-written {@link HttpExchange} for the transport tests — a real subclass
   * of the abstract JDK type, not a mock framework. Only the methods the bridge
   * actually calls are wired; the rest fail fast.
   */
  private static final class TestHttpExchange extends HttpExchange {
    private URI uri = URI.create("/");
    private String method = "GET";
    private InputStream requestBody = new ByteArrayInputStream(new byte[0]);
    private final Headers responseHeaders = new Headers();
    private final ByteArrayOutputStream responseBody = new ByteArrayOutputStream();
    private int responseStatus = -1;

    TestHttpExchange withUri(URI uri) {
      this.uri = uri;
      return this;
    }

    TestHttpExchange withMethod(String method) {
      this.method = method;
      return this;
    }

    TestHttpExchange withRequestBody(InputStream in) {
      this.requestBody = in;
      return this;
    }

    @Override public URI getRequestURI() {
      return uri;
    }

    @Override public String getRequestMethod() {
      return method;
    }

    @Override public InputStream getRequestBody() {
      return requestBody;
    }

    @Override public Headers getResponseHeaders() {
      return responseHeaders;
    }

    @Override public void sendResponseHeaders(int code, long length) {
      this.responseStatus = code;
    }

    @Override public OutputStream getResponseBody() {
      return responseBody;
    }

    @Override public int getResponseCode() {
      return responseStatus;
    }

    @Override public void close() {
      // no-op
    }

    @Override public Headers getRequestHeaders() {
      return new Headers();
    }

    @Override public HttpContext getHttpContext() {
      throw new UnsupportedOperationException();
    }

    @Override public InetSocketAddress getRemoteAddress() {
      return new InetSocketAddress(0);
    }

    @Override public InetSocketAddress getLocalAddress() {
      return new InetSocketAddress(0);
    }

    @Override public String getProtocol() {
      return "HTTP/1.1";
    }

    @Override public Object getAttribute(String name) {
      return null;
    }

    @Override public void setAttribute(String name, Object value) {
      // no-op
    }

    @Override public void setStreams(InputStream i, OutputStream o) {
      // no-op
    }

    @Override public HttpPrincipal getPrincipal() {
      return null;
    }
  }
}
