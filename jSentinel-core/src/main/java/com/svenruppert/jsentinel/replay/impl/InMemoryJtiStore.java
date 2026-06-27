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
package com.svenruppert.jsentinel.replay.impl;

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.replay.api.JtiStore;
import com.svenruppert.jsentinel.replay.api.ReplayError;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Supplier;

/**
 * In-memory {@link JtiStore} (V00.79): a sliding window of seen {@code jti}s with an
 * LRU cap (default 100k). A {@code jti} seen within its validity window is a replay;
 * once a {@code jti}'s {@code expiresAt} has passed it may be recorded again (its
 * proof's window is over). For a single JVM only — a multi-node deployment needs a
 * shared store. Thread-safe (synchronised).
 */
@ExperimentalJSentinelApi
public final class InMemoryJtiStore implements JtiStore {

  /** Default LRU cap. */
  public static final int DEFAULT_MAX_ENTRIES = 100_000;

  private final int maxEntries;
  private final Supplier<Instant> clock;
  private final Map<String, Instant> seen;

  public InMemoryJtiStore() {
    this(DEFAULT_MAX_ENTRIES, Instant::now);
  }

  public InMemoryJtiStore(int maxEntries, Supplier<Instant> clock) {
    if (maxEntries < 1) {
      throw new IllegalArgumentException("maxEntries must be >= 1");
    }
    this.maxEntries = maxEntries;
    this.clock = Objects.requireNonNull(clock, "clock");
    this.seen = new LinkedHashMap<>(256, 0.75f, true) {
      @Override
      protected boolean removeEldestEntry(Map.Entry<String, Instant> eldest) {
        return size() > InMemoryJtiStore.this.maxEntries;
      }
    };
  }

  @Override
  public synchronized Result<Boolean, ReplayError> record(String jti, Instant expiresAt) {
    Objects.requireNonNull(jti, "jti");
    Objects.requireNonNull(expiresAt, "expiresAt");
    Instant now = clock.get();
    Instant existing = seen.get(jti);
    if (existing != null && existing.isAfter(now)) {
      return Result.failure(ReplayError.replayDetected());
    }
    seen.put(jti, expiresAt);
    return Result.success(Boolean.TRUE);
  }
}
