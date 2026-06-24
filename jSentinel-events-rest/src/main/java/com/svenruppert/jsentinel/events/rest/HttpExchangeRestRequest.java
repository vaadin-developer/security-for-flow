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

import com.svenruppert.jsentinel.rest.BodyRestRequest;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Adapts a JDK {@link HttpExchange} to jSentinel-rest's {@link BodyRestRequest}
 * so the bridge can reuse the existing {@code RestSubjectResolver} contract.
 */
final class HttpExchangeRestRequest implements BodyRestRequest {

  private final HttpExchange exchange;
  private final byte[] body;

  HttpExchangeRestRequest(HttpExchange exchange, byte[] body) {
    this.exchange = exchange;
    this.body = body;
  }

  static HttpExchangeRestRequest read(HttpExchange exchange) {
    try (InputStream in = exchange.getRequestBody()) {
      return new HttpExchangeRestRequest(exchange, in.readAllBytes());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  @Override
  public String method() {
    return exchange.getRequestMethod();
  }

  @Override
  public String path() {
    return exchange.getRequestURI().getPath();
  }

  @Override
  public Map<String, String> headers() {
    Map<String, String> flat = new LinkedHashMap<>();
    for (Map.Entry<String, List<String>> e : exchange.getRequestHeaders().entrySet()) {
      if (!e.getValue().isEmpty()) {
        flat.put(e.getKey(), e.getValue().get(0));
      }
    }
    return flat;
  }

  @Override
  public Map<String, String> queryParameters() {
    Map<String, String> params = new LinkedHashMap<>();
    // Raw query: URI.getQuery() would already %-decode, so decoding it again
    // double-decodes a literal %2B; split the raw form and decode each token once.
    String query = exchange.getRequestURI().getRawQuery();
    if (query == null || query.isBlank()) {
      return params;
    }
    for (String pair : query.split("&")) {
      int eq = pair.indexOf('=');
      if (eq >= 0) {
        params.put(decode(pair.substring(0, eq)), decode(pair.substring(eq + 1)));
      } else {
        params.put(decode(pair), "");
      }
    }
    return params;
  }

  /**
   * Percent-decodes a query-string token (UTF-8). {@code +} decodes to a space,
   * {@code %XX} to its byte — so a handler sees {@code "a b"} for {@code "a%20b"}
   * (V00.75.10, H6: the raw {@code split}/{@code substring} left values encoded).
   */
  private static String decode(String raw) {
    return URLDecoder.decode(raw, StandardCharsets.UTF_8);
  }

  @Override
  public byte[] bodyBytes() {
    return body.clone();
  }
}
