package com.svenruppert.jsentinel.jwt.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * The outcome of a single JWKS refresh. In-process only — the optional
 * {@code error} is never serialized, logged with a stack trace, or carried into
 * an event payload (event types carry a sanitized message instead).
 *
 * @param keyCount  the number of keys fetched (0 on failure)
 * @param fetchedAt when the fetch completed (or was attempted)
 * @param ttl       the cache TTL derived from {@code Cache-Control}, or the default
 * @param error     the failure cause, if the refresh failed
 * @since 00.76.00
 */
@ExperimentalJSentinelApi
public record JwksRefreshResult(
    int keyCount,
    Instant fetchedAt,
    Duration ttl,
    Optional<Throwable> error) {

  public JwksRefreshResult {
    fetchedAt = Objects.requireNonNull(fetchedAt, "fetchedAt");
    ttl = Objects.requireNonNull(ttl, "ttl");
    error = Objects.requireNonNull(error, "error");
  }

  /** @return {@code true} if the refresh succeeded (no error). */
  public boolean succeeded() {
    return error.isEmpty();
  }
}
