package eu.jsentinel.jcustos.events.persistence.eclipsestore;

/*-
 * #%L
 * jCustos Events — Eclipse-Store persistence
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.events.api.EventEnvelopeId;
import eu.jsentinel.jcustos.events.replay.JCustosEventReplayStore;
import eu.jsentinel.jcustos.util.CapacityBound;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Eclipse-Store-backed {@link JCustosEventReplayStore}. Unlike the in-memory
 * default it survives JVM restarts (Konzept §1072). {@code markSeen} is atomic
 * via the storage write lock.
 */
final class EclipseStoreReplayStore implements JCustosEventReplayStore {

  private final EclipseStoreEventStorage storage;
  private final int maxEntries;

  EclipseStoreReplayStore(EclipseStoreEventStorage storage) {
    this(storage, CapacityBound.DEFAULT_MAX_ENTRIES);
  }

  EclipseStoreReplayStore(EclipseStoreEventStorage storage, int maxEntries) {
    this.storage = storage;
    this.maxEntries = CapacityBound.requirePositiveCapacity(maxEntries);
  }

  @Override
  public boolean markSeen(EventEnvelopeId envelopeId, Instant expiresAt) {
    Objects.requireNonNull(envelopeId, "envelopeId");
    Objects.requireNonNull(expiresAt, "expiresAt");
    storage.lock().writeLock().lock();
    try {
      Map<String, Long> seen = storage.root().seenEnvelopes;
      if (seen.containsKey(envelopeId.value())) {
        return false;
      }
      // JS-SEC-050 (CWE-770): this production-recommended persistent store had no bound and nothing
      // schedules purgeExpired, so it grew forever. When full, fold the expiry purge into the write
      // path (the replay window == the envelope TTL, so this keeps the map proportional to in-window
      // traffic); if still full of live entries evict the soonest-to-expire one. Over-retention is
      // safe — an expired envelope is rejected upstream, so replay protection never fails open.
      // Exit-review F1 (accepted CWE-770 tradeoff): evicting the soonest-to-expire *live* entry means
      // that single envelope could in principle be replayed before its real expiry, but only under a
      // flood of maxEntries (100k) distinct in-window ids, and evicting the minimal-remaining-window
      // entry is the least-bad choice versus unbounded growth (OOM). Raise maxEntries if that flood is
      // a realistic threat for the deployment.
      if (seen.size() >= maxEntries) {
        long now = System.currentTimeMillis();
        seen.values().removeIf(expiry -> expiry <= now);
        if (seen.size() >= maxEntries) {
          seen.entrySet().stream()
              .min(Map.Entry.comparingByValue())
              .map(Map.Entry::getKey)
              .ifPresent(seen::remove);
        }
      }
      seen.put(envelopeId.value(), expiresAt.toEpochMilli());
      storage.manager().store(seen);
      return true;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public boolean hasSeen(EventEnvelopeId envelopeId) {
    Objects.requireNonNull(envelopeId, "envelopeId");
    storage.lock().readLock().lock();
    try {
      return storage.root().seenEnvelopes.containsKey(envelopeId.value());
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void purgeExpired(Instant now) {
    Objects.requireNonNull(now, "now");
    long cutoff = now.toEpochMilli();
    storage.lock().writeLock().lock();
    try {
      Map<String, Long> seen = storage.root().seenEnvelopes;
      seen.values().removeIf(expiry -> expiry <= cutoff);
      storage.manager().store(seen);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }
}
