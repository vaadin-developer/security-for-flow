package eu.jsentinel.jcustos.jwt.impl;

/*-
 * #%L
 * jCustos JWT — standardized JWT validation
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
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
import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.jwt.api.JwksClient;
import eu.jsentinel.jcustos.jwt.api.JwksRefreshResult;
import eu.jsentinel.jcustos.jwt.api.JwsAlgorithm;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
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
 * cache (Konzept §9, §16): TTL from {@code Cache-Control: max-age} (default
 * 5 min), a single synchronous refresh on a {@code kid} miss with single-flight
 * stampede protection, a 30-second negative cache on endpoint failures, and a
 * post-miss refresh throttle (JS-SEC-001 / CWE-770): when a refresh does not
 * resolve the sought {@code kid} — a genuinely unknown kid, reachable before
 * signature verification — a short window is opened so a stream of distinct
 * unknown kids cannot force one network refresh each. A hot rotation whose kid
 * arrives outside an open throttle window resolves on the next refresh; a
 * rotation that coincides with a window just opened by a prior unknown-kid probe
 * may be delayed up to {@code REFRESH_MIN_INTERVAL} and then loaded — a bounded,
 * self-limiting availability tradeoff, not a correctness or security issue.
 *
 * <p>HTTPS is enforced at construction (JS-SEC-018 / CWE-319): a non-loopback
 * {@code jwks_uri} must use {@code https://} — the JWKS is the public-key trust
 * root, so cleartext transport invites key substitution and token forgery. A
 * loopback host ({@code localhost} / {@code 127.0.0.1} / {@code ::1}) may use
 * {@code http://} so local dev and test stubs work; the DX bootstrap keeps its
 * own STRICT {@code jwks/uri-not-https} rule for defense in depth.
 *
 * @since 00.76.00
 */
@ExperimentalJCustosApi
public final class HttpJwksClient implements JwksClient, HasLogger {

  private static final Duration DEFAULT_TTL = Duration.ofMinutes(5);
  /** JS-SEC-033 (CWE-613): upper clamp on an endpoint-advertised Cache-Control max-age. */
  private static final Duration MAX_TTL = Duration.ofHours(24);
  private static final Duration NEGATIVE_TTL = Duration.ofSeconds(30);
  /** JS-SEC-001: min interval before another unknown-kid miss may force a refresh. */
  private static final Duration REFRESH_MIN_INTERVAL = Duration.ofSeconds(20);
  private static final Pattern MAX_AGE = Pattern.compile("max-age\\s*=\\s*(\\d+)");
  private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(10);
  /** RF01: a JWKS document is a few KB; a larger body is a hostile / MITM'd endpoint. */
  private static final int MAX_JWKS_BYTES = 1 << 20;

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
    this.jwksUri = requireHttpsOrLoopback(Objects.requireNonNull(jwksUri, "jwksUri"));
    this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
    this.clock = Objects.requireNonNull(clock, "clock");
  }

  // JS-SEC-018 (CWE-319): the JWKS is the public-key trust root; loading it over
  // cleartext http lets an on-path attacker substitute keys and forge tokens.
  // Enforce https for any non-loopback endpoint; loopback http is allowed for
  // local dev / test stubs (the class contract).
  private static URI requireHttpsOrLoopback(URI uri) {
    String scheme = uri.getScheme();
    if ("https".equalsIgnoreCase(scheme)) {
      return uri;
    }
    if ("http".equalsIgnoreCase(scheme) && isLoopback(uri.getHost())) {
      return uri;
    }
    throw new IllegalArgumentException(
        "jwks/uri-not-https: JWKS endpoint must use https:// (got: " + uri + ")");
  }

  private static boolean isLoopback(String host) {
    return "localhost".equalsIgnoreCase(host)
        || "127.0.0.1".equals(host)
        || "::1".equals(host)
        || "[::1]".equals(host);
  }

  @Override
  public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
    // R10 (V00.76.10): a JWS whose header omits `kid` cannot select a key from a
    // keyed JWKS set. The cache maps are immutable (Map.of()/Map.copyOf), and
    // Map#get(null) throws NPE on them — so a kid-less token arriving during the
    // negative-cache or post-refresh window (lines below) would throw an
    // unhandled NPE that escapes validate() instead of returning empty. Guard
    // here and honour the contract ("empty if no key is known").
    if (kid == null) {
      return Optional.empty();
    }
    State snapshot = state;
    Instant now = clock.get();
    boolean fresh = now.isBefore(snapshot.expiry);
    if (fresh && snapshot.keys.containsKey(kid)) {
      return Optional.ofNullable(snapshot.keys.get(kid));
    }
    // stale, or a kid miss (hot rotation): refresh once — unless we are inside a
    // negative-cache window, in which case serve whatever we still hold.
    if (now.isBefore(snapshot.negativeUntil)) {
      return Optional.ofNullable(snapshot.keys.get(kid));
    }
    refreshOnce();
    PublicKey key = state.keys.get(kid);
    if (key == null) {
      // JS-SEC-001 (CWE-770): the refresh did not resolve this kid — it is
      // genuinely unknown, not a hot rotation. Open a short throttle window so a
      // stream of distinct unknown kids cannot each force a network refresh.
      openUnknownKidThrottle();
    }
    return Optional.ofNullable(key);
  }

  /** Opens (or extends) the unknown-kid refresh-throttle window (JS-SEC-001). */
  private void openUnknownKidThrottle() {
    Instant until = clock.get().plus(REFRESH_MIN_INTERVAL);
    lock.lock();
    try {
      State s = state;
      Instant neg = s.negativeUntil.isAfter(until) ? s.negativeUntil : until;
      this.state = new State(s.keys, s.expiry, neg);
    } finally {
      lock.unlock();
    }
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
      HttpResponse<InputStream> response =
          httpClient.send(request, HttpResponse.BodyHandlers.ofInputStream());
      if (response.statusCode() / 100 != 2) {
        response.body().close();
        logger().warn("jwks/refresh-non-2xx: status={}", response.statusCode());
        return new FetchOutcome(new JwksRefreshResult(0, now, NEGATIVE_TTL,
            Optional.of("Non2xxResponse")), null);
      }
      // RF01: read at most MAX_JWKS_BYTES + 1; a larger body is rejected before parsing
      // (the 10s timeout caps time, not size).
      byte[] bytes;
      try (InputStream in = response.body()) {
        bytes = in.readNBytes(MAX_JWKS_BYTES + 1);
      }
      if (bytes.length > MAX_JWKS_BYTES) {
        logger().warn("jwks/refresh-oversized: body exceeds {} bytes", MAX_JWKS_BYTES);
        return new FetchOutcome(new JwksRefreshResult(0, now, NEGATIVE_TTL,
            Optional.of("OversizedBody")), null);
      }
      Map<String, PublicKey> keys = parse(new String(bytes, StandardCharsets.UTF_8));
      return new FetchOutcome(
          new JwksRefreshResult(keys.size(), now, ttlFrom(response), Optional.empty()), keys);
    } catch (RuntimeException | IOException | ParseException e) {
      logger().warn("jwks/refresh-failed: {}", e.getClass().getSimpleName());
      return new FetchOutcome(
          new JwksRefreshResult(0, now, NEGATIVE_TTL, Optional.of(e.getClass().getSimpleName())), null);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return new FetchOutcome(
          new JwksRefreshResult(0, now, NEGATIVE_TTL, Optional.of(e.getClass().getSimpleName())), null);
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

  private static Duration ttlFrom(HttpResponse<?> response) {
    Optional<String> cacheControl = response.headers().firstValue("Cache-Control");
    if (cacheControl.isPresent()) {
      Matcher m = MAX_AGE.matcher(cacheControl.get());
      if (m.find()) {
        try {
          long seconds = Long.parseLong(m.group(1));
          if (seconds > 0) {
            // JS-SEC-033 (CWE-613): clamp an endpoint-controlled max-age to a sane
            // maximum so a hostile/misconfigured IdP cannot pin a (possibly revoked)
            // key set far into the future — this bounds the revocation-propagation window.
            return Duration.ofSeconds(Math.min(seconds, MAX_TTL.toSeconds()));
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
