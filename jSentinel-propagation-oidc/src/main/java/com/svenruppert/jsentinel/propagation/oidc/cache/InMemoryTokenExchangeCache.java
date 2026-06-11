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
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * In-process {@link TokenExchangeCache}. Soft-skew TTL — entries are
 * considered expired {@code skewSeconds} before their advertised
 * {@code expiresAt}.
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public final class InMemoryTokenExchangeCache implements TokenExchangeCache {

  /** Default skew applied to {@code expiresAt} (30 seconds). */
  public static final long DEFAULT_SKEW_SECONDS = 30L;

  private final ConcurrentMap<String, CachedEntry> entries = new ConcurrentHashMap<>();
  private final Clock clock;
  private final long skewSeconds;

  public InMemoryTokenExchangeCache() {
    this(Clock.systemUTC(), DEFAULT_SKEW_SECONDS);
  }

  public InMemoryTokenExchangeCache(Clock clock, long skewSeconds) {
    this.clock = clock;
    this.skewSeconds = skewSeconds;
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
    entries.put(key, value);
  }

  @Override
  public void clear() {
    entries.clear();
  }
}
