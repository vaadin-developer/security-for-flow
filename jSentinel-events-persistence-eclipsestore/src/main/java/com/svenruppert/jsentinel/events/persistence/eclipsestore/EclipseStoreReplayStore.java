package com.svenruppert.jsentinel.events.persistence.eclipsestore;

/*-
 * #%L
 * jSentinel Events — Eclipse-Store persistence
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

import com.svenruppert.jsentinel.events.api.EventEnvelopeId;
import com.svenruppert.jsentinel.events.replay.JSentinelEventReplayStore;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;

/**
 * Eclipse-Store-backed {@link JSentinelEventReplayStore}. Unlike the in-memory
 * default it survives JVM restarts (Konzept §1072). {@code markSeen} is atomic
 * via the storage write lock.
 */
final class EclipseStoreReplayStore implements JSentinelEventReplayStore {

  private final EclipseStoreEventStorage storage;

  EclipseStoreReplayStore(EclipseStoreEventStorage storage) {
    this.storage = storage;
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
