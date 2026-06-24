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

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.events.api.EventProducerId;
import com.svenruppert.jsentinel.events.api.EventSequence;
import com.svenruppert.jsentinel.events.sequence.JSentinelEventSequenceStore;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * Eclipse-Store-backed {@link JSentinelEventSequenceStore}. The per-{@code
 * (tenant, producer)} counter survives restart; updates are atomic via the
 * storage write lock (Konzept §1072, §322).
 */
final class EclipseStoreSequenceStore implements JSentinelEventSequenceStore {

  private final EclipseStoreEventStorage storage;

  EclipseStoreSequenceStore(EclipseStoreEventStorage storage) {
    this.storage = storage;
  }

  private static String key(TenantId tenantId, EventProducerId producerId) {
    return Objects.requireNonNull(tenantId, "tenantId").value()
        + '|' + Objects.requireNonNull(producerId, "producerId").value();
  }

  @Override
  public Optional<EventSequence> lastSequence(TenantId tenantId, EventProducerId producerId) {
    String key = key(tenantId, producerId);
    storage.lock().readLock().lock();
    try {
      return Optional.ofNullable(storage.root().sequences.get(key)).map(EventSequence::of);
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public void updateSequence(TenantId tenantId, EventProducerId producerId,
      EventSequence sequence) {
    Objects.requireNonNull(sequence, "sequence");
    String key = key(tenantId, producerId);
    storage.lock().writeLock().lock();
    try {
      Map<String, Long> sequences = storage.root().sequences;
      sequences.put(key, sequence.value());
      storage.manager().store(sequences);
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  // R011: the whole read-advance-write runs under the storage write lock, so two
  // publishers for the same scope can never reserve the same sequence.
  @Override
  public EventSequence reserveNext(TenantId tenantId, EventProducerId producerId) {
    String key = key(tenantId, producerId);
    storage.lock().writeLock().lock();
    try {
      Map<String, Long> sequences = storage.root().sequences;
      Long last = sequences.get(key);
      EventSequence next = last == null ? EventSequence.FIRST : EventSequence.of(last).next();
      sequences.put(key, next.value());
      storage.manager().store(sequences);
      return next;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }
}
