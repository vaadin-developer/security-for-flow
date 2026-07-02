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
package com.svenruppert.jsentinel.oauth2;

/*-
 * #%L
 * jSentinel OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
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

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.oauth2.api.ClientAuthentication;
import com.svenruppert.jsentinel.oauth2.api.IntrospectionClient;
import com.svenruppert.jsentinel.oauth2.api.IntrospectionResult;
import com.svenruppert.jsentinel.oauth2.api.OAuth2Error;
import com.svenruppert.jsentinel.oauth2.api.TokenTypeHint;
import com.svenruppert.jsentinel.oauth2.internal.OAuth2FormPost;
import com.svenruppert.jsentinel.oauth2.internal.OAuth2Json;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * RFC 7662 token introspection over JDK {@link HttpClient} (V00.77). Caches each
 * decision keyed by the SHA-256 of the token for {@link #DEFAULT_TTL_MILLIS} (a
 * bounded LRU map), so a hot access token is not re-introspected on every request
 * while a revoked token still leaves the cache within the TTL. The raw token is
 * never used as a cache key and never logged.
 */
public final class HttpIntrospectionClient implements IntrospectionClient {

  /** Default positive/negative cache TTL. */
  public static final long DEFAULT_TTL_MILLIS = 60_000L;
  private static final int MAX_CACHE_ENTRIES = 4_096;
  private static final String CODE = "oauth2/introspection-endpoint";

  private final HttpClient http;
  private final URI endpoint;
  private final ClientAuthentication clientAuthentication;
  private final long ttlMillis;
  private final Map<String, CacheEntry> cache;

  private record CacheEntry(IntrospectionResult result, long expiresAtMillis) {
  }

  public HttpIntrospectionClient(HttpClient http, URI endpoint,
      ClientAuthentication clientAuthentication) {
    this(http, endpoint, clientAuthentication, DEFAULT_TTL_MILLIS);
  }

  public HttpIntrospectionClient(HttpClient http, URI endpoint,
      ClientAuthentication clientAuthentication, long ttlMillis) {
    this.http = Objects.requireNonNull(http, "http");
    this.endpoint = OAuth2FormPost.requireHttps(Objects.requireNonNull(endpoint, "endpoint"), CODE);
    this.clientAuthentication = Objects.requireNonNull(clientAuthentication, "clientAuthentication");
    if (ttlMillis < 0) {
      throw new IllegalArgumentException("ttlMillis must be >= 0");
    }
    this.ttlMillis = ttlMillis;
    this.cache = new LinkedHashMap<>(64, 0.75f, false) {
      @Override
      protected boolean removeEldestEntry(Map.Entry<String, CacheEntry> eldest) {
        return size() > MAX_CACHE_ENTRIES;
      }
    };
  }

  @Override
  public Result<IntrospectionResult, OAuth2Error> introspect(String token, TokenTypeHint hint) {
    Objects.requireNonNull(token, "token");
    Objects.requireNonNull(hint, "hint");
    String key = sha256(token);
    long now = System.currentTimeMillis();

    synchronized (cache) {
      CacheEntry hit = cache.get(key);
      if (hit != null && hit.expiresAtMillis() > now) {
        return Result.success(hit.result());
      }
    }

    Map<String, String> form = new LinkedHashMap<>();
    form.put("token", token);
    form.put("token_type_hint", hint.wire());
    Result<IntrospectionResult, OAuth2Error> result =
        OAuth2FormPost.post(http, endpoint, form, clientAuthentication).flatMap(outcome -> {
          if (outcome.status() < 200 || outcome.status() >= 300) {
            return Result.failure(new OAuth2Error.EndpointError(outcome.status()));
          }
          return Result.success(parse(outcome.body()));
        });
    result.toOptional().ifPresent(parsed -> {
      // JS-SEC-006 (CWE-613): cap the positive cache entry at the token's own
      // exp, so an opaque token is never reported active past its real expiry
      // — the RS has no other way to check exp for opaque tokens.
      long expiry = parsed.expiresAt()
          .map(Instant::toEpochMilli)
          .map(exp -> Math.min(now + ttlMillis, exp))
          .orElse(now + ttlMillis);
      synchronized (cache) {
        cache.put(key, new CacheEntry(parsed, expiry));
      }
    });
    return result;
  }

  private static IntrospectionResult parse(String body) {
    boolean active = OAuth2Json.bool(body, "active").orElse(false);
    if (!active) {
      return IntrospectionResult.inactive();
    }
    Set<String> scopes = OAuth2Json.string(body, "scope")
        .filter(s -> !s.isBlank())
        .map(s -> Set.of(s.trim().split("\\s+")))
        .orElse(Set.of());
    return new IntrospectionResult(true, scopes,
        OAuth2Json.string(body, "client_id"),
        OAuth2Json.string(body, "username"),
        OAuth2Json.longValue(body, "exp").map(Instant::ofEpochSecond),
        OAuth2Json.longValue(body, "iat").map(Instant::ofEpochSecond),
        OAuth2Json.string(body, "token_type"),
        OAuth2Json.string(body, "aud"),
        OAuth2Json.string(body, "iss"),
        OAuth2Json.string(body, "jti"));
  }

  private static String sha256(String token) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      return HexFormat.of().formatHex(md.digest(token.getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException("SHA-256 unavailable", e);
    }
  }
}
