/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.demo.rest.shared.DemoEndpoints;
import com.svenruppert.vaadin.security.rest.RestAuthorizationFilter;
import com.svenruppert.vaadin.security.rest.RestHandler;
import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Method;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Routes incoming {@link HttpExchange} requests to demo handlers and applies
 * the generic {@link RestAuthorizationFilter} for permission-protected paths.
 */
public final class DemoHttpRouter implements HttpHandler {

  private final DemoHandlers handlers;
  private final DemoBootstrapHandlers bootstrapHandlers;
  private final DemoSubjectResolver subjectResolver;
  private final RestAuthorizationFilter filter;

  private final Method listDocumentsMethod;
  private final Method createDocumentMethod;
  private final Method deleteDocumentMethod;
  private final Method adminStatusMethod;

  public DemoHttpRouter(
      DemoHandlers handlers,
      DemoBootstrapHandlers bootstrapHandlers,
      DemoSubjectResolver subjectResolver) {
    this.handlers = handlers;
    this.bootstrapHandlers = bootstrapHandlers;
    this.subjectResolver = subjectResolver;
    this.filter = new RestAuthorizationFilter(subjectResolver);
    try {
      Class<?>[] sig = {
          com.svenruppert.vaadin.security.rest.RestRequest.class,
          com.svenruppert.vaadin.security.rest.RestResponse.class
      };
      this.listDocumentsMethod = DemoHandlers.class.getDeclaredMethod("listDocuments", sig);
      this.createDocumentMethod = DemoHandlers.class.getDeclaredMethod("createDocument", sig);
      this.deleteDocumentMethod = DemoHandlers.class.getDeclaredMethod("deleteDocument", sig);
      this.adminStatusMethod = DemoHandlers.class.getDeclaredMethod("adminStatus", sig);
    } catch (NoSuchMethodException e) {
      throw new IllegalStateException("Demo handler method missing", e);
    }
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    try {
      DemoHttpRequest request = readRequest(exchange);
      DemoHttpResponse response = new DemoHttpResponse();
      dispatch(request, response);
      writeResponse(exchange, response);
    } catch (RuntimeException e) {
      DemoHttpResponse fallback = new DemoHttpResponse();
      fallback.status(500);
      fallback.body("Internal Server Error");
      writeResponse(exchange, fallback);
    } finally {
      exchange.close();
    }
  }

  private void dispatch(DemoHttpRequest request, DemoHttpResponse response) {
    String method = request.method();
    String path = request.path();

    if (DemoEndpoints.BOOTSTRAP_STATUS.equals(path) && "GET".equals(method)) {
      bootstrapHandlers.status(request, response);
      return;
    }
    if (DemoEndpoints.BOOTSTRAP_ADMIN.equals(path) && "POST".equals(method)) {
      bootstrapHandlers.createInitialAdmin(request, response);
      return;
    }
    if (DemoEndpoints.LOGIN.equals(path) && "POST".equals(method)) {
      handlers.login(request, response);
      return;
    }
    if (DemoEndpoints.ME.equals(path) && "GET".equals(method)) {
      requireAuthenticated(request, response, handlers::me);
      return;
    }
    if (DemoEndpoints.OPERATIONS.equals(path) && "GET".equals(method)) {
      requireAuthenticated(request, response, handlers::operations);
      return;
    }
    if (DemoEndpoints.LOGOUT.equals(path) && "POST".equals(method)) {
      requireAuthenticated(request, response, handlers::logout);
      return;
    }
    if (DemoEndpoints.DOCUMENTS.equals(path)) {
      switch (method) {
        case "GET" -> filter.authorizeAndHandle(request, response, handlers::listDocuments, listDocumentsMethod);
        case "POST" -> filter.authorizeAndHandle(request, response, handlers::createDocument, createDocumentMethod);
        default -> notAllowed(response);
      }
      return;
    }
    if (path.startsWith(DemoEndpoints.DOCUMENT_BY_ID) && "DELETE".equals(method)) {
      filter.authorizeAndHandle(request, response, handlers::deleteDocument, deleteDocumentMethod);
      return;
    }
    if (DemoEndpoints.ADMIN_STATUS.equals(path) && "GET".equals(method)) {
      filter.authorizeAndHandle(request, response, handlers::adminStatus, adminStatusMethod);
      return;
    }
    response.status(404);
    response.body("Not Found");
  }

  private void requireAuthenticated(DemoHttpRequest request, DemoHttpResponse response, RestHandler handler) {
    if (subjectResolver.resolveSubject(request).isEmpty()) {
      response.status(401);
      response.body("Unauthorized");
      return;
    }
    handler.handle(request, response);
  }

  private static void notAllowed(DemoHttpResponse response) {
    response.status(405);
    response.body("Method Not Allowed");
  }

  private static DemoHttpRequest readRequest(HttpExchange exchange) throws IOException {
    String body;
    try (InputStream in = exchange.getRequestBody()) {
      body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
    URI uri = exchange.getRequestURI();
    return new DemoHttpRequest(
        exchange.getRequestMethod(),
        uri.getPath(),
        flattenHeaders(exchange.getRequestHeaders()),
        parseQuery(uri.getRawQuery()),
        body);
  }

  private static Map<String, String> flattenHeaders(Headers headers) {
    Map<String, String> map = new LinkedHashMap<>();
    for (var entry : headers.entrySet()) {
      if (!entry.getValue().isEmpty()) {
        map.put(entry.getKey(), entry.getValue().get(0));
      }
    }
    return map;
  }

  private static Map<String, String> parseQuery(String rawQuery) {
    Map<String, String> map = new LinkedHashMap<>();
    if (rawQuery == null || rawQuery.isEmpty()) return map;
    for (String pair : rawQuery.split("&")) {
      int eq = pair.indexOf('=');
      if (eq < 0) {
        map.put(URLDecoder.decode(pair, StandardCharsets.UTF_8), "");
      } else {
        String k = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
        String v = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
        map.put(k, v);
      }
    }
    return map;
  }

  private static void writeResponse(HttpExchange exchange, DemoHttpResponse response) throws IOException {
    byte[] payload = response.getBody().getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", "application/json; charset=utf-8");
    int contentLength = payload.length == 0 ? -1 : payload.length;
    exchange.sendResponseHeaders(response.status(), contentLength);
    if (payload.length > 0) {
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(payload);
      }
    }
  }
}
