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
package eu.jsentinel.jcustos.propagation.oidc.strategy;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.propagation.HeaderValue;
import eu.jsentinel.jcustos.credential.propagation.OutboundCall;
import eu.jsentinel.jcustos.credential.propagation.OutboundTokenStrategy;
import eu.jsentinel.jcustos.credential.propagation.TokenCredential;
import eu.jsentinel.jcustos.propagation.oidc.cache.InMemoryTokenExchangeCache;
import eu.jsentinel.jcustos.propagation.oidc.cache.TokenExchangeCache;
import eu.jsentinel.jcustos.propagation.oidc.http.JsonResponse;
import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.dependencies.core.net.MediaType;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * RFC 8693 OAuth 2.0 Token Exchange strategy. Exchanges the inbound
 * bearer token for a token minted for the downstream audience.
 *
 * <p>HTTPS-only by default; the constructor accepts plain
 * {@code http://localhost} when the system property
 * {@code jcustos.dev=true} is set (development carve-out).
 *
 * <p>Hard-fails on 4xx / 5xx via {@link JCustosPropagationException}
 * — there is no silent fallback to the no-header path.
 *
 * @since 00.74.00
 */
@ExperimentalJCustosApi
public final class TokenExchangeStrategy implements OutboundTokenStrategy, HasLogger {

  private static final String AUTHORIZATION = "Authorization";

  /** Stable lookup key. */
  public static final String NAME = "exchange";

  private final URI tokenEndpoint;
  private final String clientId;
  private final String clientSecret;
  private final HttpClient http;
  private final TokenExchangeCache cache;

  /** Convenience: default {@link HttpClient} + {@link InMemoryTokenExchangeCache}. */
  public TokenExchangeStrategy(URI tokenEndpoint, String clientId, String clientSecret) {
    this(tokenEndpoint, clientId, clientSecret, HttpClient.newHttpClient(),
        new InMemoryTokenExchangeCache());
  }

  public TokenExchangeStrategy(URI tokenEndpoint, String clientId, String clientSecret,
                               HttpClient http, TokenExchangeCache cache) {
    if (tokenEndpoint == null) throw new IllegalArgumentException("tokenEndpoint");
    validateHttps(tokenEndpoint);
    this.tokenEndpoint = tokenEndpoint;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.http = http;
    this.cache = cache;
  }

  private static void validateHttps(URI endpoint) {
    String scheme = endpoint.getScheme();
    if ("https".equalsIgnoreCase(scheme)) return;
    boolean devMode = Boolean.getBoolean("jcustos.dev");
    boolean localhost = "localhost".equalsIgnoreCase(endpoint.getHost())
        || "127.0.0.1".equals(endpoint.getHost());
    if (devMode && localhost && "http".equalsIgnoreCase(scheme)) return;
    throw new IllegalArgumentException(
        "propagation/endpoint-not-https: token endpoint must use https:// "
            + "(got: " + endpoint + "). Use http://localhost only with -Djcustos.dev=true.");
  }

  @Override
  public String name() {
    return NAME;
  }

  @Override
  public Optional<HeaderValue> resolve(OutboundCall call, Optional<TokenCredential> inbound) {
    // JS-SEC-044 (CWE-522): a Class-A RefreshToken / ApiKey must never be sent to the token endpoint
    // as an RFC 8693 subject_token — it would leak (mislabeled as an access_token) via the outbound
    // call. Defer to the single shared decision on TokenCredential, matching PassThroughStrategy.
    if (inbound.isEmpty() || !inbound.get().isForwardableAsSubjectToken()) {
      return Optional.empty();
    }
    String subject = inbound.get().value();
    String key = cacheKey(subject, call.declaredAudience());
    Optional<TokenExchangeCache.CachedEntry> cached = cache.get(key);
    if (cached.isPresent()) {
      return Optional.of(new HeaderValue(AUTHORIZATION, "Bearer " + cached.get().accessToken()));
    }
    String body = formBody(subject, call.declaredAudience());
    HttpRequest request = HttpRequest.newBuilder(tokenEndpoint)
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .header("Content-Type", MediaType.APPLICATION_FORM_URLENCODED.mime())
        .timeout(Duration.ofSeconds(10))
        .build();
    // JS-SEC-036 (CWE-770): bounded read — reject an oversized token-endpoint body.
    BoundedTokenHttp.Response response = BoundedTokenHttp.send(http, request);
    if (response.statusCode() < 200 || response.statusCode() >= 300) {
      // R010: never put the token-endpoint body in the exception message — OAuth
      // error bodies carry error_description and on a misconfig can echo grant
      // material, and this exception propagates into logs. The thrown message
      // carries only the status code; the body is logged truncated at DEBUG.
      logger().debug("Token endpoint returned HTTP {} (body truncated): {}",
          response.statusCode(), truncateBody(response.body()));
      throw new JCustosPropagationException(response.statusCode(),
          "Token endpoint returned HTTP " + response.statusCode());
    }
    String accessToken = JsonResponse.accessToken(response.body())
        .orElseThrow(() -> new JCustosPropagationException(response.statusCode(),
            "Token endpoint response missing access_token"));
    long expiresIn = JsonResponse.expiresIn(response.body()).orElse(60L);
    cache.put(key, new TokenExchangeCache.CachedEntry(
        accessToken, Instant.now().plusSeconds(expiresIn)));
    return Optional.of(new HeaderValue(AUTHORIZATION, "Bearer " + accessToken));
  }

  /**
   * R023: the cache must never be keyed on the raw inbound bearer token — that
   * places a live credential verbatim in the cache map (heap dumps / diagnostics
   * leak it). Key on a SHA-256 digest of the token instead: a stable,
   * non-reversible identifier. The raw token is still used for the actual
   * exchange request body, never as a stored key.
   */
  private static String cacheKey(String subjectToken, String audience) {
    return sha256Hex(subjectToken) + "|" + audience;
  }

  private static String sha256Hex(String value) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256")
          .digest(value.getBytes(StandardCharsets.UTF_8));
      StringBuilder sb = new StringBuilder(digest.length * 2);
      for (byte b : digest) {
        sb.append(Character.forDigit((b >> 4) & 0xF, 16))
            .append(Character.forDigit(b & 0xF, 16));
      }
      return sb.toString();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 is required but unavailable", e);
    }
  }

  /** Caps a diagnostic body so a large/hostile error response can't flood the log. */
  private static String truncateBody(String body) {
    if (body == null) {
      return "";
    }
    return body.length() <= 256 ? body : body.substring(0, 256) + "…(truncated)";
  }

  private String formBody(String subject, String audience) {
    StringBuilder sb = new StringBuilder();
    append(sb, "grant_type", "urn:ietf:params:oauth:grant-type:token-exchange");
    append(sb, "subject_token", subject);
    append(sb, "subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
    if (!audience.isEmpty()) append(sb, "audience", audience);
    if (clientId != null) append(sb, "client_id", clientId);
    if (clientSecret != null) append(sb, "client_secret", clientSecret);
    return sb.toString();
  }

  private static void append(StringBuilder sb, String name, String value) {
    if (sb.length() > 0) sb.append('&');
    sb.append(URLEncoder.encode(name, StandardCharsets.UTF_8))
      .append('=')
      .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
  }
}
