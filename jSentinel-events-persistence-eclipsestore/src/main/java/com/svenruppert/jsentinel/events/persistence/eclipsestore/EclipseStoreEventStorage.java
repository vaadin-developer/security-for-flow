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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.events.replay.JSentinelEventReplayStore;
import com.svenruppert.jsentinel.events.sequence.JSentinelEventSequenceStore;
import com.svenruppert.jsentinel.events.store.JSentinelEventDeadLetterStore;
import com.svenruppert.jsentinel.events.store.JSentinelEventEnvelopeStore;
import com.svenruppert.jsentinel.persistence.eclipsestore.StorageTreeHardening;
import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Eclipse-Store-backed storage for the Security Event Bus persistent stores
 * (Konzept §1070): replay, sequence, dead-letter and (optional) envelope store,
 * all in one embedded storage. Survives JVM restarts.
 *
 * <p>Opens its own {@link EmbeddedStorageManager}; a {@link
 * ReentrantReadWriteLock} serializes writes so {@code markSeen} stays atomic.
 * The root object is implementation-internal.
 *
 * @since 00.75.00
 */
@ExperimentalJSentinelApi
public final class EclipseStoreEventStorage implements AutoCloseable, HasLogger {

  private final EmbeddedStorageManager manager;
  private final EventStorageRoot root;
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
  private boolean closed;

  private EclipseStoreEventStorage(EmbeddedStorageManager manager, EventStorageRoot root) {
    this.manager = manager;
    this.root = root;
  }

  /**
   * Opens (or creates) the event storage at the given directory.
   *
   * @param storageDirectory the storage directory
   * @return a started storage facade
   */
  public static EclipseStoreEventStorage openAt(Path storageDirectory) {
    Objects.requireNonNull(storageDirectory, "storageDirectory");
    // JS-SEC-037 (CWE-276): harden owner-only before EmbeddedStorage.start so the persisted
    // security-event feed (signed envelopes with subject ids, dead-letters, replay ids) is
    // never group/other-readable under a default umask. RF (exit-review): shares the single
    // StorageTreeHardening home with the framework persistence module (was a private copy).
    StorageTreeHardening.hardenOwnerOnly(storageDirectory, "events-persistence/storage-permissions",
        "the store holds signed security-event envelopes with subject ids");
    EmbeddedStorageManager manager = EmbeddedStorage.start(storageDirectory);
    EventStorageRoot root;
    if (manager.root() instanceof EventStorageRoot existing) {
      root = existing;
    } else {
      root = new EventStorageRoot();
      manager.setRoot(root);
      manager.storeRoot();
    }
    migrateResolvedDeadLetters(manager, root);
    EclipseStoreEventStorage storage = new EclipseStoreEventStorage(manager, root);
    // R03: rewrite legacy raw tenant|producer sequence keys to the framed v2 format —
    // exactly once per open, under the storage write lock (same discipline as every
    // sequence-store mutation), before the facade is handed out.
    storage.lock.writeLock().lock();
    try {
      EclipseStoreSequenceStore.migrateLegacySequenceKeys(manager, root);
    } finally {
      storage.lock.writeLock().unlock();
    }
    return storage;
  }

  /**
   * JS-SEC-052 (CWE-770): one-time drain of the legacy append-only {@code resolvedDeadLetters} set.
   * Any id still there is an already-resolved dead letter (its heavy record was dropped by R07) or a
   * legacy pre-R07 record that must now be dropped; remove any matching record and clear the set so
   * it can never grow again. Idempotent — a later open finds an empty set and does nothing.
   */
  private static void migrateResolvedDeadLetters(EmbeddedStorageManager manager, EventStorageRoot root) {
    if (root.resolvedDeadLetters.isEmpty()) {
      return;
    }
    for (String id : root.resolvedDeadLetters) {
      root.deadLetters.remove(id);
    }
    root.resolvedDeadLetters.clear();
    manager.store(root.deadLetters);
    manager.store(root.resolvedDeadLetters);
  }

  EventStorageRoot root() {
    return root;
  }

  EmbeddedStorageManager manager() {
    return manager;
  }

  ReentrantReadWriteLock lock() {
    return lock;
  }

  /** @return the persistent replay store. */
  public JSentinelEventReplayStore replayStore() {
    return new EclipseStoreReplayStore(this);
  }

  /** @return the persistent sequence store. */
  public JSentinelEventSequenceStore sequenceStore() {
    return new EclipseStoreSequenceStore(this);
  }

  /** @return the persistent envelope store. */
  public JSentinelEventEnvelopeStore envelopeStore() {
    return new EclipseStoreEnvelopeStore(this);
  }

  /** @return the persistent dead-letter store. */
  public JSentinelEventDeadLetterStore deadLetterStore() {
    return new EclipseStoreDeadLetterStore(this);
  }

  /**
   * Shuts the storage manager down. Idempotent.
   *
   * <p>R04: a {@code closed} guard (taken under the write lock, so it is
   * thread-safe and ordered against in-flight writes) makes the second and
   * later calls genuine no-ops — previously a double close (destroy listener +
   * JVM shutdown hook) hit an already-shut manager. Mirrors the R033 guard on
   * {@code EclipseStoreJSentinelStorage}.
   */
  @Override
  public void close() {
    lock.writeLock().lock();
    try {
      if (closed) {
        return;
      }
      closed = true;
      manager.shutdown();
    } finally {
      lock.writeLock().unlock();
    }
  }
}
