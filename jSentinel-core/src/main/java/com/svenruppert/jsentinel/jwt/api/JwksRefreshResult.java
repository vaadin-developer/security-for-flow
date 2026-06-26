package com.svenruppert.jsentinel.jwt.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Optional;

/**
 * The outcome of a single JWKS refresh. In-process only.
 *
 * <p>F3 (V00.76.10): the failure is exposed as {@code errorClass} — a short,
 * non-secret failure descriptor (the cause's class simple name, or a synthetic
 * failure-kind token) — rather than the live {@code Throwable} it used to carry.
 * The old {@code Optional<Throwable>} was a foot-gun: a logger or consumer could
 * print the full cause (endpoint URLs / status in messages, a stack trace) and
 * defeat the "never leak internals" promise. {@code errorClass} is safe to log
 * and to surface; it never holds a message or a stack trace.
 *
 * @param keyCount   the number of keys fetched (0 on failure)
 * @param fetchedAt  when the fetch completed (or was attempted)
 * @param ttl        the cache TTL derived from {@code Cache-Control}, or the default
 * @param errorClass the failure descriptor, if the refresh failed; empty on success
 * @since 00.76.00
 */
@ExperimentalJSentinelApi
public record JwksRefreshResult(
    int keyCount,
    Instant fetchedAt,
    Duration ttl,
    Optional<String> errorClass) {

  public JwksRefreshResult {
    fetchedAt = Objects.requireNonNull(fetchedAt, "fetchedAt");
    ttl = Objects.requireNonNull(ttl, "ttl");
    errorClass = Objects.requireNonNull(errorClass, "errorClass");
  }

  /** @return {@code true} if the refresh succeeded (no error). */
  public boolean succeeded() {
    return errorClass.isEmpty();
  }
}
