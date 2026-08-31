/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.propagation.oidc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;

/**
 * In-process token-endpoint stub for V00.74 OIDC strategy tests. Port
 * 0 so the OS picks a free port. Returns a canned response per
 * {@code grant_type} (raw substring match — good enough for tests).
 *
 * @since 00.74.00
 */
public final class StubTokenEndpoint {

  private final HttpServer server;
  private final int port;
  private volatile Response next = new Response(200,
      "{\"access_token\":\"stub-token\",\"token_type\":\"Bearer\",\"expires_in\":3600}");

  public StubTokenEndpoint() throws IOException {
    this.server = HttpServer.create(new InetSocketAddress(0), 0);
    this.server.createContext("/token", this::handle);
    this.server.start();
    this.port = server.getAddress().getPort();
  }

  public int port() {
    return port;
  }

  public URI tokenEndpoint() {
    return URI.create("http://localhost:" + port + "/token");
  }

  /** Override the canned response. */
  public void respondWith(Response response) {
    this.next = response;
  }

  public void stop() {
    server.stop(0);
  }

  private void handle(HttpExchange exchange) throws IOException {
    Response r = this.next;
    byte[] body = r.body().getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    exchange.sendResponseHeaders(r.status(), body.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(body);
    }
  }

  public record Response(int status, String body) {
  }
}
