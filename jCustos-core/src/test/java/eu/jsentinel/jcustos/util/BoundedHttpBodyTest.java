package eu.jsentinel.jcustos.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * CWE-400: a server that answers the headers promptly and then trickles the
 * body holds the calling thread. The request timeout does not help when the
 * body is read after {@code send} has already returned.
 */
@DisplayName("BoundedHttpBody — the request timeout must bound the body too (CWE-400)")
class BoundedHttpBodyTest {

  private HttpServer server;
  private URI baseUri;

  @BeforeEach
  void startServer() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    baseUri = URI.create("http://127.0.0.1:" + server.getAddress().getPort());

    // Headers immediately, then one byte every 300 ms — the slow-loris shape.
    server.createContext("/trickle", exchange -> {
      exchange.sendResponseHeaders(200, 0);
      try (OutputStream out = exchange.getResponseBody()) {
        for (int i = 0; i < 200; i++) {
          out.write('x');
          out.flush();
          Thread.sleep(300);
        }
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      } catch (IOException expected) {
        // client gave up — that is the point of the test
      }
    });

    server.createContext("/small", exchange -> {
      byte[] body = "ok".getBytes();
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    });

    server.createContext("/huge", exchange -> {
      byte[] body = new byte[64 * 1024];
      exchange.sendResponseHeaders(200, body.length);
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(body);
      }
    });

    server.start();
  }

  @AfterEach
  void stopServer() {
    server.stop(0);
  }

  @Test
  @DisplayName("a trickling body hits the request timeout instead of hanging")
  void tricklingBodyTimesOut() {
    HttpClient http = HttpClient.newHttpClient();
    HttpRequest request = HttpRequest.newBuilder(baseUri.resolve("/trickle"))
        .timeout(Duration.ofSeconds(2))
        .GET().build();

    Instant start = Instant.now();
    assertThrows(Exception.class,
        () -> http.send(request, BoundedHttpBody.ofByteArray(1024)),
        "the exchange must fail rather than wait for a 60-second drip");
    Duration elapsed = Duration.between(start, Instant.now());

    assertTrue(elapsed.compareTo(Duration.ofSeconds(10)) < 0,
        "the timeout must cover the body read; took " + elapsed);
  }

  @Test
  @DisplayName("a normal body is returned unchanged")
  void normalBodyPasses() throws Exception {
    HttpClient http = HttpClient.newHttpClient();
    HttpResponse<byte[]> response = http.send(
        HttpRequest.newBuilder(baseUri.resolve("/small")).GET().build(),
        BoundedHttpBody.ofByteArray(1024));

    assertEquals(200, response.statusCode());
    assertEquals("ok", new String(response.body()));
  }

  @Test
  @DisplayName("a body past the cap fails the exchange rather than truncating it")
  void oversizedBodyFails() {
    HttpClient http = HttpClient.newHttpClient();

    assertThrows(Exception.class, () -> http.send(
            HttpRequest.newBuilder(baseUri.resolve("/huge")).GET().build(),
            BoundedHttpBody.ofByteArray(1024)),
        "a truncated body must never be mistaken for a complete one");
  }

  @Test
  @DisplayName("a non-positive cap is rejected")
  void nonPositiveCapRejected() {
    assertThrows(IllegalArgumentException.class, () -> BoundedHttpBody.ofByteArray(0));
    assertThrows(IllegalArgumentException.class, () -> BoundedHttpBody.ofByteArray(-1));
  }
}
