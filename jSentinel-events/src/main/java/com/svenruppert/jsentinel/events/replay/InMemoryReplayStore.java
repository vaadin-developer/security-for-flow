package com.svenruppert.jsentinel.events.replay;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
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

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.api.EventEnvelopeId;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * In-memory {@link JSentinelEventReplayStore} backed by a bounded map.
 *
 * <p>All access is synchronized so {@link #markSeen(EventEnvelopeId, Instant)}
 * is atomic. When the capacity bound is hit, the entry with the
 * <strong>soonest expiry</strong> is evicted — i.e. the one closest to being
 * purgeable anyway — rather than the least-recently-used one. The old LRU policy
 * (V00.75.00) could drop a still-valid id while keeping an expired-but-recently-
 * checked one, opening an in-window replay (V00.75.20, R012). Still not
 * JVM-restart-safe; use the persistent variant for cross-restart guarantees.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class InMemoryReplayStore implements JSentinelEventReplayStore {

  /** Default bound on the number of retained envelope ids. */
  public static final int DEFAULT_CAPACITY = 100_000;

  private final Map<EventEnvelopeId, Instant> seen = new LinkedHashMap<>();
  private final int capacity;

  public InMemoryReplayStore() {
    this(DEFAULT_CAPACITY);
  }

  public InMemoryReplayStore(int capacity) {
    if (capacity < 1) {
      throw new IllegalArgumentException("capacity must be >= 1, was " + capacity);
    }
    this.capacity = capacity;
  }

  @Override
  public synchronized boolean markSeen(EventEnvelopeId envelopeId, Instant expiresAt) {
    Objects.requireNonNull(envelopeId, "envelopeId");
    Objects.requireNonNull(expiresAt, "expiresAt");
    if (seen.containsKey(envelopeId)) {
      return false;
    }
    if (seen.size() >= capacity) {
      // Evict the soonest-to-expire entry (smallest expiresAt) — it has the
      // shortest remaining replay window, so dropping it is the least unsafe.
      seen.entrySet().stream()
          .min(Map.Entry.comparingByValue())
          .map(Map.Entry::getKey)
          .ifPresent(seen::remove);
    }
    seen.put(envelopeId, expiresAt);
    return true;
  }

  @Override
  public synchronized boolean hasSeen(EventEnvelopeId envelopeId) {
    return seen.containsKey(Objects.requireNonNull(envelopeId, "envelopeId"));
  }

  @Override
  public synchronized void purgeExpired(Instant now) {
    Objects.requireNonNull(now, "now");
    Iterator<Map.Entry<EventEnvelopeId, Instant>> it = seen.entrySet().iterator();
    while (it.hasNext()) {
      Instant expiresAt = it.next().getValue();
      if (!expiresAt.isAfter(now)) {
        it.remove();
      }
    }
  }

  /**
   * @return the current number of retained entries (test/diagnostic aid)
   */
  public synchronized int size() {
    return seen.size();
  }
}
