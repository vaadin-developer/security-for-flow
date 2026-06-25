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
package com.svenruppert.jsentinel.propagation.oidc.strategy;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.credential.propagation.HeaderValue;
import com.svenruppert.jsentinel.credential.propagation.OutboundCall;
import com.svenruppert.jsentinel.credential.propagation.OutboundTokenStrategy;
import com.svenruppert.jsentinel.credential.propagation.TokenCredential;
import com.svenruppert.jsentinel.propagation.oidc.cache.InMemoryTokenExchangeCache;
import com.svenruppert.jsentinel.propagation.oidc.cache.TokenExchangeCache;
import com.svenruppert.jsentinel.propagation.oidc.http.JsonResponse;
import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.dependencies.core.net.MediaType;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * RFC 6749 §4.4 Client Credentials strategy. Ignores the inbound
 * token — this is service-to-service authentication.
 *
 * <p>Same HTTPS discipline and hard-fail-on-non-2xx contract as
 * {@link TokenExchangeStrategy}.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public final class ClientCredentialsStrategy implements OutboundTokenStrategy, HasLogger {

  private static final String AUTHORIZATION = "Authorization";

  /** Default lookup key. */
  public static final String NAME = "service";

  private final URI tokenEndpoint;
  private final String clientId;
  private final String clientSecret;
  private final HttpClient http;
  private final TokenExchangeCache cache;
  private final String name;

  public static ClientCredentialsStrategy forClient(URI tokenEndpoint,
                                                    String clientId,
                                                    String clientSecret) {
    return new ClientCredentialsStrategy(tokenEndpoint, clientId, clientSecret,
        HttpClient.newHttpClient(), new InMemoryTokenExchangeCache(), NAME);
  }

  public ClientCredentialsStrategy(URI tokenEndpoint, String clientId, String clientSecret,
                                   HttpClient http, TokenExchangeCache cache, String name) {
    if (tokenEndpoint == null) throw new IllegalArgumentException("tokenEndpoint");
    validateHttps(tokenEndpoint);
    this.tokenEndpoint = tokenEndpoint;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.http = http;
    this.cache = cache;
    this.name = (name == null || name.isEmpty()) ? NAME : name;
  }

  private static void validateHttps(URI endpoint) {
    String scheme = endpoint.getScheme();
    if ("https".equalsIgnoreCase(scheme)) return;
    boolean devMode = Boolean.getBoolean("jsentinel.dev");
    boolean localhost = "localhost".equalsIgnoreCase(endpoint.getHost())
        || "127.0.0.1".equals(endpoint.getHost());
    if (devMode && localhost && "http".equalsIgnoreCase(scheme)) return;
    throw new IllegalArgumentException(
        "propagation/endpoint-not-https: token endpoint must use https:// "
            + "(got: " + endpoint + ").");
  }

  @Override
  public String name() {
    return name;
  }

  @Override
  public Optional<HeaderValue> resolve(OutboundCall call, Optional<TokenCredential> inbound) {
    String key = clientId + "|" + call.declaredAudience();
    Optional<TokenExchangeCache.CachedEntry> cached = cache.get(key);
    if (cached.isPresent()) {
      return Optional.of(new HeaderValue(AUTHORIZATION, "Bearer " + cached.get().accessToken()));
    }
    String body = formBody(call);
    HttpRequest request = HttpRequest.newBuilder(tokenEndpoint)
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED.mime())
        .timeout(Duration.ofSeconds(10))
        .build();
    HttpResponse<String> response;
    try {
      response = http.send(request, HttpResponse.BodyHandlers.ofString());
    } catch (Exception e) {
      throw new JSentinelPropagationException(0,
          "Token endpoint call failed: " + e.getMessage(), e);
    }
    if (response.statusCode() < 200 || response.statusCode() >= 300) {
      // R010: never put the token-endpoint body in the exception message — OAuth
      // error bodies carry error_description and on a misconfig can echo grant
      // material, and this exception propagates into logs. The thrown message
      // carries only the status code; the body is logged truncated at DEBUG.
      logger().debug("Token endpoint returned HTTP {} (body truncated): {}",
          response.statusCode(), truncateBody(response.body()));
      throw new JSentinelPropagationException(response.statusCode(),
          "Token endpoint returned HTTP " + response.statusCode());
    }
    String accessToken = JsonResponse.accessToken(response.body())
        .orElseThrow(() -> new JSentinelPropagationException(response.statusCode(),
            "Token endpoint response missing access_token"));
    long expiresIn = JsonResponse.expiresIn(response.body()).orElse(60L);
    cache.put(key, new TokenExchangeCache.CachedEntry(
        accessToken, Instant.now().plusSeconds(expiresIn)));
    return Optional.of(new HeaderValue(AUTHORIZATION, "Bearer " + accessToken));
  }

  /** Caps a diagnostic body so a large/hostile error response can't flood the log. */
  private static String truncateBody(String body) {
    if (body == null) {
      return "";
    }
    return body.length() <= 256 ? body : body.substring(0, 256) + "…(truncated)";
  }

  private String formBody(OutboundCall call) {
    StringBuilder sb = new StringBuilder();
    append(sb, "grant_type", "client_credentials");
    if (clientId != null) append(sb, "client_id", clientId);
    if (clientSecret != null) append(sb, "client_secret", clientSecret);
    if (!call.declaredAudience().isEmpty()) append(sb, "audience", call.declaredAudience());
    String scope = call.hints().getOrDefault("scope", "");
    if (!scope.isEmpty()) append(sb, "scope", scope);
    return sb.toString();
  }

  private static void append(StringBuilder sb, String name, String value) {
    if (sb.length() > 0) sb.append('&');
    sb.append(URLEncoder.encode(name, StandardCharsets.UTF_8))
      .append('=')
      .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
  }
}
