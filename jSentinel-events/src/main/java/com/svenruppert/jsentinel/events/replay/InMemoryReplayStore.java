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
import com.svenruppert.jsentinel.util.CapacityBound;

import java.time.Instant;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.NavigableMap;
import java.util.Objects;
import java.util.TreeMap;

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

  private final Map<EventEnvelopeId, Instant> seen = new HashMap<>();
  // R08 (V00.76.10): a secondary expiry-ordered index so soonest-to-expire
  // eviction and purge are O(log n) / O(k) instead of a full O(n) min-scan on
  // every insert at capacity. Multiple ids can share an expiry instant, so each
  // key maps to the set of ids with that expiry (insertion-ordered for
  // determinism). seen and byExpiry are kept consistent under `synchronized`.
  private final NavigableMap<Instant, LinkedHashSet<EventEnvelopeId>> byExpiry = new TreeMap<>();
  private final int capacity;

  /**
   * Creates a store bounded to {@link CapacityBound#DEFAULT_MAX_ENTRIES}
   * retained envelope ids — the single-home capacity contract shared by every
   * attacker-keyed in-memory store (R06, CWE-770).
   */
  public InMemoryReplayStore() {
    this(CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  /**
   * Creates a store bounded to {@code capacity} retained envelope ids.
   *
   * @param capacity the upper bound; must be positive
   * @throws IllegalArgumentException if {@code capacity < 1}
   */
  public InMemoryReplayStore(int capacity) {
    this.capacity = CapacityBound.requirePositiveCapacity(capacity);
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
      // O(log n) via the expiry-ordered index instead of an O(n) min-scan.
      Map.Entry<Instant, LinkedHashSet<EventEnvelopeId>> soonest = byExpiry.firstEntry();
      LinkedHashSet<EventEnvelopeId> ids = soonest.getValue();
      EventEnvelopeId victim = ids.iterator().next();
      ids.remove(victim);
      if (ids.isEmpty()) {
        byExpiry.remove(soonest.getKey());
      }
      seen.remove(victim);
    }
    seen.put(envelopeId, expiresAt);
    byExpiry.computeIfAbsent(expiresAt, k -> new LinkedHashSet<>()).add(envelopeId);
    return true;
  }

  @Override
  public synchronized boolean hasSeen(EventEnvelopeId envelopeId) {
    return seen.containsKey(Objects.requireNonNull(envelopeId, "envelopeId"));
  }

  @Override
  public synchronized void purgeExpired(Instant now) {
    Objects.requireNonNull(now, "now");
    // Entries are expired when expiresAt <= now, i.e. the head of the expiry
    // index up to and including `now`. headMap(now, true) is that prefix in
    // O(log n + k); removing through the view drops them from byExpiry too.
    NavigableMap<Instant, LinkedHashSet<EventEnvelopeId>> expired = byExpiry.headMap(now, true);
    for (LinkedHashSet<EventEnvelopeId> ids : expired.values()) {
      for (EventEnvelopeId id : ids) {
        seen.remove(id);
      }
    }
    expired.clear();
  }

  /**
   * @return the current number of retained entries (test/diagnostic aid)
   */
  public synchronized int size() {
    return seen.size();
  }
}
