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
package com.svenruppert.jsentinel.propagation.oidc.cache;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.time.Clock;
import java.time.Instant;
import java.util.Comparator;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-process {@link TokenExchangeCache}. Soft-skew TTL — entries are
 * considered expired {@code skewSeconds} before their advertised
 * {@code expiresAt}.
 * <p>
 * Bounded (JS-SEC-015 / CWE-770): the map is capped at {@code maxEntries}; a
 * {@code put} over the bound first sweeps expired entries and then evicts the
 * soonest-to-expire one, so a high-churn / rotating-token workload cannot grow
 * it without limit or keep expired access tokens resident indefinitely. (Access
 * tokens are {@code String}s and cannot be zeroized; eviction drops the
 * reference for GC.)
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public final class InMemoryTokenExchangeCache implements TokenExchangeCache {

  /** Default skew applied to {@code expiresAt} (30 seconds). */
  public static final long DEFAULT_SKEW_SECONDS = 30L;

  /** Default upper bound on cached entries (JS-SEC-015). */
  public static final int DEFAULT_MAX_ENTRIES = 10_000;

  private final ConcurrentMap<String, CachedEntry> entries = new ConcurrentHashMap<>();
  private final Clock clock;
  private final long skewSeconds;
  private final int maxEntries;

  public InMemoryTokenExchangeCache() {
    this(Clock.systemUTC(), DEFAULT_SKEW_SECONDS, DEFAULT_MAX_ENTRIES);
  }

  public InMemoryTokenExchangeCache(Clock clock, long skewSeconds) {
    this(clock, skewSeconds, DEFAULT_MAX_ENTRIES);
  }

  public InMemoryTokenExchangeCache(Clock clock, long skewSeconds, int maxEntries) {
    if (maxEntries < 1) {
      throw new IllegalArgumentException("maxEntries must be >= 1");
    }
    this.clock = clock;
    this.skewSeconds = skewSeconds;
    this.maxEntries = maxEntries;
  }

  @Override
  public Optional<CachedEntry> get(String key) {
    CachedEntry e = entries.get(key);
    if (e == null) return Optional.empty();
    Instant nowSkewed = Instant.now(clock).plusSeconds(skewSeconds);
    if (!nowSkewed.isBefore(e.expiresAt())) {
      entries.remove(key, e);
      return Optional.empty();
    }
    return Optional.of(e);
  }

  @Override
  public void put(String key, CachedEntry value) {
    // JS-SEC-015 (CWE-770): keep the map bounded. Sweep expired entries first,
    // then evict the soonest-to-expire if still at the cap, before inserting.
    if (entries.size() >= maxEntries && !entries.containsKey(key)) {
      sweepExpired();
      if (entries.size() >= maxEntries) {
        evictSoonestToExpire();
      }
    }
    entries.put(key, value);
  }

  private void sweepExpired() {
    Instant nowSkewed = Instant.now(clock).plusSeconds(skewSeconds);
    entries.values().removeIf(e -> !nowSkewed.isBefore(e.expiresAt()));
  }

  private void evictSoonestToExpire() {
    entries.entrySet().stream()
        .min(Comparator.comparing(e -> e.getValue().expiresAt()))
        .ifPresent(e -> entries.remove(e.getKey(), e.getValue()));
  }

  @Override
  public void clear() {
    entries.clear();
  }
}
