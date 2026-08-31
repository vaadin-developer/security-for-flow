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
package eu.jsentinel.jcustos.persistence.eclipsestore;

import eu.jsentinel.jcustos.ratelimiting.RateLimitKey;
import eu.jsentinel.jcustos.ratelimiting.RateLimitStore;

import java.time.Instant;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.Map;

import static java.util.Objects.requireNonNull;

/** Eclipse-Store-backed {@link RateLimitStore}. */
final class EclipseStoreRateLimitStore implements RateLimitStore {

  private final EclipseStoreJSentinelStorage storage;

  EclipseStoreRateLimitStore(EclipseStoreJSentinelStorage storage) {
    this.storage = storage;
  }

  @Override
  public void recordEvent(RateLimitKey key, Instant at) {
    requireNonNull(key, "key must not be null");
    requireNonNull(at, "at must not be null");
    storage.lock().writeLock().lock();
    try {
      LinkedHashSet<Instant> events = storage.root().rateLimitEvents.get(key);
      boolean newKey = events == null;
      if (newKey) {
        events = new LinkedHashSet<>();
        storage.root().rateLimitEvents.put(key, events);
      }
      events.add(at);
      // Eclipse Store persists only the object actually stored. An in-place
      // mutation of an already-persisted set is NOT captured by storing the
      // parent map (R002), so store the mutated set itself; for a brand-new key
      // also store the map to persist the new key->set entry.
      storage.manager().store(events);
      if (newKey) {
        storage.manager().store(storage.root().rateLimitEvents);
      }
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public int countSince(RateLimitKey key, Instant since) {
    requireNonNull(key, "key must not be null");
    requireNonNull(since, "since must not be null");
    storage.lock().readLock().lock();
    try {
      LinkedHashSet<Instant> events = storage.root().rateLimitEvents.get(key);
      if (events == null) {
        return 0;
      }
      int count = 0;
      for (Instant event : events) {
        if (!event.isBefore(since)) {
          count++;
        }
      }
      return count;
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void reset(RateLimitKey key) {
    requireNonNull(key, "key must not be null");
    storage.lock().writeLock().lock();
    try {
      if (storage.root().rateLimitEvents.remove(key) != null) {
        storage.manager().store(storage.root().rateLimitEvents);
      }
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public int purgeOlderThan(Instant cutoff) {
    requireNonNull(cutoff, "cutoff must not be null");
    storage.lock().writeLock().lock();
    try {
      int purged = 0;
      boolean entriesRemoved = false;
      Iterator<Map.Entry<RateLimitKey, LinkedHashSet<Instant>>> entries =
          storage.root().rateLimitEvents.entrySet().iterator();
      while (entries.hasNext()) {
        LinkedHashSet<Instant> events = entries.next().getValue();
        boolean setMutated = false;
        Iterator<Instant> it = events.iterator();
        while (it.hasNext()) {
          if (it.next().isBefore(cutoff)) {
            it.remove();
            purged++;
            setMutated = true;
          }
        }
        if (events.isEmpty()) {
          entries.remove();
          entriesRemoved = true;
        } else if (setMutated) {
          // persist the in-place set mutation — store(map) would not re-store
          // an already-persisted nested set (R002).
          storage.manager().store(events);
        }
      }
      if (entriesRemoved) {
        // entry removals mutate the map itself, which store(map) does persist.
        storage.manager().store(storage.root().rateLimitEvents);
      }
      return purged;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }
}
