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

import com.svenruppert.jsentinel.events.store.DeadLetterId;
import com.svenruppert.jsentinel.events.store.JSentinelEventDeadLetter;
import com.svenruppert.jsentinel.events.store.JSentinelEventDeadLetterStore;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Eclipse-Store-backed {@link JSentinelEventDeadLetterStore} (Konzept §1073).
 * Insertion order is preserved so {@link #findOpen(int)} returns oldest-first.
 */
final class EclipseStoreDeadLetterStore implements JSentinelEventDeadLetterStore {

  private final EclipseStoreEventStorage storage;

  EclipseStoreDeadLetterStore(EclipseStoreEventStorage storage) {
    this.storage = storage;
  }

  @Override
  public void store(JSentinelEventDeadLetter deadLetter) {
    Objects.requireNonNull(deadLetter, "deadLetter");
    storage.lock().writeLock().lock();
    try {
      Map<String, JSentinelEventDeadLetter> records = storage.root().deadLetters;
      records.put(deadLetter.id().value(), deadLetter);
      storage.manager().store(records);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public List<JSentinelEventDeadLetter> findOpen(int limit) {
    if (limit < 0) {
      throw new IllegalArgumentException("limit must be >= 0, was " + limit);
    }
    storage.lock().readLock().lock();
    try {
      Set<String> resolved = storage.root().resolvedDeadLetters;
      List<JSentinelEventDeadLetter> open = new ArrayList<>();
      for (JSentinelEventDeadLetter record : storage.root().deadLetters.values()) {
        if (open.size() >= limit) {
          break;
        }
        if (!resolved.contains(record.id().value())) {
          open.add(record);
        }
      }
      return open;
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void markResolved(DeadLetterId id) {
    Objects.requireNonNull(id, "id");
    storage.lock().writeLock().lock();
    try {
      // R07 (V00.76.10): drop the heavy record (it embeds a full signed envelope) so resolved dead
      // letters cannot accumulate without bound.
      //
      // JS-SEC-052 (CWE-770): DO NOT also append the id to resolvedDeadLetters. Because the record is
      // deleted, findOpen can never surface it again, and the ids are random UUIDs so no future dead
      // letter can collide — the resolved-id set was pure append-only, never-pruned growth that
      // uniquely defeated the R07 "cannot grow without bound" guarantee the InMemory reference
      // honours. Legacy already-persisted resolved ids are drained by the one-time startup migration
      // in EclipseStoreEventStorage, so findOpen (which still filters against the now-emptied set)
      // needs nothing here.
      Map<String, JSentinelEventDeadLetter> records = storage.root().deadLetters;
      records.remove(id.value());
      storage.manager().store(records);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }
}
