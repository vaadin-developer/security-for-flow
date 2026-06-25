package com.svenruppert.jsentinel.jwt.impl;

/*-
 * #%L
 * jSentinel JWT — standardized JWT validation
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

import com.nimbusds.jose.jwk.AsymmetricJWK;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.jwt.api.JwksClient;
import com.svenruppert.jsentinel.jwt.api.JwksRefreshResult;
import com.svenruppert.jsentinel.jwt.api.JwsAlgorithm;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * {@link JwksClient} that fetches a JWKS document over HTTP with a disciplined
 * cache (Konzept §9): TTL from {@code Cache-Control: max-age} (default 5 min),
 * a single synchronous refresh on a {@code kid} miss with single-flight stampede
 * protection, and a 30-second negative cache on endpoint failures so a transient
 * outage cannot turn into a DoS against the IDP.
 *
 * <p>HTTPS is <em>not</em> enforced here — that is a bootstrap-time STRICT rule
 * ({@code jwks/uri-not-https}); the client serves whatever URI it is given so
 * loopback test stubs work.
 *
 * @since 00.76.00
 */
@ExperimentalJSentinelApi
public final class HttpJwksClient implements JwksClient, HasLogger {

  private static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
  private static final Duration NEGATIVE_TTL = Duration.ofSeconds(30);
  private static final Pattern MAX_AGE = Pattern.compile("max-age\\s*=\\s*(\\d+)");
  private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);

  private final URI jwksUri;
  private final HttpClient httpClient;
  private final Supplier<Instant> clock;

  private final ReentrantLock lock = new ReentrantLock();
  private volatile State state = new State(Map.of(), Instant.EPOCH, Instant.EPOCH);
  private CompletableFuture<JwksRefreshResult> inFlight;

  public HttpJwksClient(URI jwksUri) {
    this(jwksUri, HttpClient.newBuilder().connectTimeout(HTTP_TIMEOUT).build(), Instant::now);
  }

  public HttpJwksClient(URI jwksUri, HttpClient httpClient, Supplier<Instant> clock) {
    this.jwksUri = Objects.requireNonNull(jwksUri, "jwksUri");
    this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  @Override
  public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
    State snapshot = state;
    Instant now = clock.get();
    boolean fresh = now.isBefore(snapshot.expiry);
    if (fresh && kid != null && snapshot.keys.containsKey(kid)) {
      return Optional.ofNullable(snapshot.keys.get(kid));
    }
    // stale, or a kid miss (hot rotation): refresh once — unless we are inside a
    // negative-cache window, in which case serve whatever we still hold.
    if (now.isBefore(snapshot.negativeUntil)) {
      return Optional.ofNullable(snapshot.keys.get(kid));
    }
    refreshOnce();
    return Optional.ofNullable(state.keys.get(kid));
  }

  @Override
  public JwksRefreshResult refreshOnce() {
    CompletableFuture<JwksRefreshResult> mine;
    boolean lead = false;
    lock.lock();
    try {
      if (inFlight == null) {
        inFlight = new CompletableFuture<>();
        lead = true;
      }
      mine = inFlight;
    } finally {
      lock.unlock();
    }

    if (!lead) {
      // a refresh is already running — wait on the leader (stampede protection).
      return mine.join();
    }

    FetchOutcome outcome = fetch();
    lock.lock();
    try {
      apply(outcome);
      inFlight = null;
    } finally {
      lock.unlock();
    }
    mine.complete(outcome.result());
    return outcome.result();
  }

  private FetchOutcome fetch() {
    Instant now = clock.get();
    try {
      HttpRequest request = HttpRequest.newBuilder(jwksUri).timeout(HTTP_TIMEOUT).GET().build();
      HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      if (response.statusCode() / 100 != 2) {
        logger().warn("jwks/refresh-non-2xx: status={}", response.statusCode());
        return new FetchOutcome(new JwksRefreshResult(0, now, NEGATIVE_TTL,
            Optional.of(new IllegalStateException("JWKS endpoint returned " + response.statusCode()))),
            null);
      }
      Map<String, PublicKey> keys = parse(response.body());
      return new FetchOutcome(
          new JwksRefreshResult(keys.size(), now, ttlFrom(response), Optional.empty()), keys);
    } catch (RuntimeException | IOException | ParseException e) {
      logger().warn("jwks/refresh-failed: {}", e.getClass().getSimpleName());
      return new FetchOutcome(new JwksRefreshResult(0, now, NEGATIVE_TTL, Optional.of(e)), null);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return new FetchOutcome(new JwksRefreshResult(0, now, NEGATIVE_TTL, Optional.of(e)), null);
    }
  }

  /** Updates the cached state from a refresh outcome. Must hold {@link #lock}. */
  private void apply(FetchOutcome outcome) {
    Instant now = outcome.result().fetchedAt();
    if (outcome.keys() != null) {
      this.state = new State(outcome.keys(), now.plus(outcome.result().ttl()), Instant.EPOCH);
    } else {
      // keep the old keys, open a negative-cache window so we do not hammer the IDP.
      this.state = new State(state.keys, state.expiry, now.plus(NEGATIVE_TTL));
    }
  }

  private static Map<String, PublicKey> parse(String body) throws ParseException {
    JWKSet set = JWKSet.parse(body);
    Map<String, PublicKey> keys = new LinkedHashMap<>();
    for (JWK jwk : set.getKeys()) {
      if (jwk.getKeyID() != null && jwk instanceof AsymmetricJWK asym) {
        try {
          keys.put(jwk.getKeyID(), asym.toPublicKey());
        } catch (com.nimbusds.jose.JOSEException ignored) {
          // skip a key we cannot materialise as a JDK PublicKey
        }
      }
    }
    return Map.copyOf(keys);
  }

  private static Duration ttlFrom(HttpResponse<String> response) {
    Optional<String> cacheControl = response.headers().firstValue("Cache-Control");
    if (cacheControl.isPresent()) {
      Matcher m = MAX_AGE.matcher(cacheControl.get());
      if (m.find()) {
        try {
          long seconds = Long.parseLong(m.group(1));
          if (seconds > 0) {
            return Duration.ofSeconds(seconds);
          }
        } catch (NumberFormatException ignored) {
          // fall through to the default
        }
      }
    }
    return DEFAULT_TTL;
  }

  /** Immutable cache snapshot for lock-free reads. */
  private record State(Map<String, PublicKey> keys, Instant expiry, Instant negativeUntil) {
  }

  /** A fetch outcome: the result plus the parsed keys (null on failure). */
  private record FetchOutcome(JwksRefreshResult result, Map<String, PublicKey> keys) {
  }
}
