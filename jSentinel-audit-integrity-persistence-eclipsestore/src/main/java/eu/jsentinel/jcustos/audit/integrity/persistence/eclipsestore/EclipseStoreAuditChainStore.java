package eu.jsentinel.jcustos.audit.integrity.persistence.eclipsestore;

/*-
 * #%L
 * jCustos Audit Integrity — Eclipse-Store persistence
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

import eu.jsentinel.jcustos.audit.integrity.api.AuditChainEntry;
import eu.jsentinel.jcustos.audit.integrity.api.AuditChainStore;

import java.util.List;
import java.util.Optional;

/**
 * Persistent {@link AuditChainStore}: the linkage CAS runs under the
 * storage's write lock (check-and-append is atomic), the appended list is
 * stored after every accepted entry, reads run under the read lock and
 * return immutable copies. There is deliberately no delete/update path —
 * the SPI contract IS the storage layout.
 */
final class EclipseStoreAuditChainStore implements AuditChainStore {

  private final EclipseStoreAuditChainStorage storage;

  EclipseStoreAuditChainStore(EclipseStoreAuditChainStorage storage) {
    this.storage = storage;
  }

  @Override
  public Optional<AuditChainEntry> head() {
    storage.lock().readLock().lock();
    try {
      storage.requireOpen();
      List<AuditChainEntry> entries = storage.root().entries;
      return entries.isEmpty()
          ? Optional.empty()
          : Optional.of(entries.get(entries.size() - 1));
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public long size() {
    storage.lock().readLock().lock();
    try {
      storage.requireOpen();
      return storage.root().entries.size();
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public boolean append(AuditChainEntry entry) {
    storage.lock().writeLock().lock();
    try {
      storage.requireOpen();
      List<AuditChainEntry> entries = storage.root().entries;
      if (entry.index() != entries.size()) {
        return false;
      }
      String expectedPrevious = entries.isEmpty()
          ? AuditChainEntry.GENESIS_PREVIOUS_HASH
          : entries.get(entries.size() - 1).entryHash();
      if (!expectedPrevious.equals(entry.previousEntryHash())) {
        return false;
      }
      entries.add(entry);
      storage.manager().store(entries);
      return true;
    } finally {
      storage.lock().writeLock().unlock();
    }
  }

  @Override
  public List<AuditChainEntry> read(long fromIndex, int maxCount) {
    if (fromIndex < 0) {
      throw new IllegalArgumentException("fromIndex must be >= 0");
    }
    if (maxCount < 1) {
      throw new IllegalArgumentException("maxCount must be >= 1");
    }
    storage.lock().readLock().lock();
    try {
      storage.requireOpen();
      List<AuditChainEntry> entries = storage.root().entries;
      if (fromIndex >= entries.size()) {
        return List.of();
      }
      int from = (int) fromIndex;
      int to = (int) Math.min(entries.size(), fromIndex + maxCount);
      return List.copyOf(entries.subList(from, to));
    } finally {
      storage.lock().readLock().unlock();
    }
  }

  @Override
  public Optional<AuditChainEntry> entryAt(long index) {
    storage.lock().readLock().lock();
    try {
      storage.requireOpen();
      List<AuditChainEntry> entries = storage.root().entries;
      if (index < 0 || index >= entries.size()) {
        return Optional.empty();
      }
      return Optional.of(entries.get((int) index));
    } finally {
      storage.lock().readLock().unlock();
    }
  }
}
