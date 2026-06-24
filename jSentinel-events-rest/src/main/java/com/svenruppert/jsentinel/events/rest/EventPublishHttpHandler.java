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
import com.svenruppert.dependencies.core.net.MediaType;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.rest.RestSubjectResolver;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;

/**
 * JDK-{@code HttpServer} endpoint for {@code POST /api/events} (Konzept §970).
 * Requires an authenticated subject holding the {@code events:publish}
 * permission, then hands the body to the {@link EventPublishService}, which runs
 * the full consume pipeline. The publish endpoint must be strictly authorized —
 * not every consumer may publish (Konzept §972).
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class EventPublishHttpHandler implements HttpHandler, HasLogger {

  private final EventPublishService publishService;
  private final RestSubjectResolver subjectResolver;
  private final PermissionName requiredPermission;

  public EventPublishHttpHandler(EventPublishService publishService,
      RestSubjectResolver subjectResolver, String requiredPermission) {
    this.publishService = Objects.requireNonNull(publishService, "publishService");
    this.subjectResolver = Objects.requireNonNull(subjectResolver, "subjectResolver");
    this.requiredPermission = new PermissionName(
        Objects.requireNonNull(requiredPermission, "requiredPermission"));
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
      write(exchange, HttpStatus.METHOD_NOT_ALLOWED.code(), "Method Not Allowed");
      return;
    }
    HttpExchangeRestRequest request = HttpExchangeRestRequest.read(exchange);

    Optional<JSentinelSubject> subject = subjectResolver.resolveSubject(request);
    if (subject.isEmpty()) {
      write(exchange, HttpStatus.UNAUTHORIZED.code(), "Unauthorized");
      return;
    }
    if (!subject.get().permissions().contains(requiredPermission)) {
      write(exchange, HttpStatus.FORBIDDEN.code(), "Forbidden");
      return;
    }

    EventPublishOutcome outcome = publishService.publish(request.bodyAsUtf8());
    write(exchange, outcome.statusCode(), outcome.body());
  }

  private static void write(HttpExchange exchange, int status, String body) throws IOException {
    byte[] payload = body.getBytes(StandardCharsets.UTF_8);
    exchange.getResponseHeaders().add("Content-Type", MediaType.TEXT_PLAIN.withCharsetUtf8());
    exchange.sendResponseHeaders(status, payload.length == 0 ? -1 : payload.length);
    if (payload.length > 0) {
      try (OutputStream out = exchange.getResponseBody()) {
        out.write(payload);
      }
    }
    exchange.close();
  }
}
