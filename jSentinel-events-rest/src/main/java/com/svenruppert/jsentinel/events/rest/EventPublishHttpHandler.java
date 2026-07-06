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
import com.svenruppert.jsentinel.audit.LogFieldScrubber;
import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionMatcher;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.rest.RestSubjectResolver;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

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

  /**
   * Default cap on the {@code POST /api/events} request body (1 MiB). Event
   * envelopes are small JSON; a larger body is rejected with {@code 413} before
   * it is buffered, so an unauthenticated client cannot OOM the server by
   * streaming an oversized body that is read ahead of authorization (R01).
   */
  public static final int DEFAULT_MAX_PUBLISH_BODY_BYTES = 1 << 20;

  private final EventPublishService publishService;
  private final RestSubjectResolver subjectResolver;
  private final PermissionName requiredPermission;
  private final int maxBodyBytes;

  public EventPublishHttpHandler(EventPublishService publishService,
      RestSubjectResolver subjectResolver, String requiredPermission) {
    this(publishService, subjectResolver, requiredPermission, DEFAULT_MAX_PUBLISH_BODY_BYTES);
  }

  public EventPublishHttpHandler(EventPublishService publishService,
      RestSubjectResolver subjectResolver, String requiredPermission, int maxBodyBytes) {
    this.publishService = Objects.requireNonNull(publishService, "publishService");
    this.subjectResolver = Objects.requireNonNull(subjectResolver, "subjectResolver");
    this.requiredPermission = new PermissionName(
        Objects.requireNonNull(requiredPermission, "requiredPermission"));
    if (maxBodyBytes < 1) {
      throw new IllegalArgumentException("maxBodyBytes must be positive");
    }
    this.maxBodyBytes = maxBodyBytes;
  }

  @Override
  public void handle(HttpExchange exchange) throws IOException {
    if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
      write(exchange, HttpStatus.METHOD_NOT_ALLOWED.code(), "Method Not Allowed");
      return;
    }
    HttpExchangeRestRequest request;
    try {
      request = HttpExchangeRestRequest.read(exchange, maxBodyBytes);
    } catch (RequestBodyTooLargeException tooLarge) {
      // reject before buffering / before authorization — pre-auth OOM guard (R01).
      logger().warn("events-rest/publish-body-too-large: {}", tooLarge.getMessage());
      write(exchange, HttpStatus.CONTENT_TOO_LARGE.code(), "Content Too Large");
      return;
    } catch (UncheckedIOException e) {
      // a body-read failure (e.g. client disconnect mid-stream) is a client
      // problem — map it to a clean 400 instead of letting the UncheckedIOException
      // propagate out of handle() and close the connection ungracefully (H6).
      logger().warn("events-rest/publish-read-failed: {}", e.getMessage());
      write(exchange, HttpStatus.BAD_REQUEST.code(), "Malformed request");
      return;
    }

    Optional<JSentinelSubject> subject = subjectResolver.resolveSubject(request);
    if (subject.isEmpty()) {
      write(exchange, HttpStatus.UNAUTHORIZED.code(), "Unauthorized");
      return;
    }
    // RF (exit-review): wildcard-aware match via PermissionMatcher — same path as
    // RequiresPermissionEvaluator — so a subject holding "events:*" is permitted
    // symmetrically with the annotation-guarded handlers (was exact-match contains()).
    if (!PermissionMatcher.containsAll(
        subject.get().permissionNames(), Set.of(requiredPermission))) {
      write(exchange, HttpStatus.FORBIDDEN.code(), "Forbidden");
      return;
    }

    // JS-SEC-054 (CWE-755) belt-and-braces: verify() is now a total function, but never let an
    // unexpected RuntimeException escape handle() — that would abort the exchange (no clean status,
    // exchange.close() skipped) and log a stack trace with un-scrubbed attacker input. Log a
    // scrubbed message and return a clean 500 so exchange.close() always runs.
    EventPublishOutcome outcome;
    try {
      outcome = publishService.publish(request.bodyAsUtf8());
    } catch (RuntimeException unexpected) {
      logger().warn("events-rest/publish-failed: {}", LogFieldScrubber.scrub(unexpected.toString()));
      write(exchange, HttpStatus.INTERNAL_SERVER_ERROR.code(), "Publish failed");
      return;
    }
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
