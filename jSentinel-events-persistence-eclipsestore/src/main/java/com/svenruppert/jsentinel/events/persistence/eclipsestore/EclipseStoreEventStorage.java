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
    EmbeddedStorageManager manager = EmbeddedStorage.start(storageDirectory);
    EventStorageRoot root;
    if (manager.root() instanceof EventStorageRoot existing) {
      root = existing;
    } else {
      root = new EventStorageRoot();
      manager.setRoot(root);
      manager.storeRoot();
    }
    return new EclipseStoreEventStorage(manager, root);
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

  @Override
  public void close() {
    manager.shutdown();
  }
}
