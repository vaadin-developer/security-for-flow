package eu.jsentinel.jcustos.audit.integrity.persistence.eclipsestore;

/*-
 * #%L
 * jSentinel Audit Integrity — Eclipse-Store persistence
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
import eu.jsentinel.jcustos.audit.integrity.api.AuditChainStore;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import eu.jsentinel.jcustos.persistence.eclipsestore.StorageTreeHardening;
import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * JVM-restart-safe home of the audit hash chain: one embedded Eclipse-Store
 * instance whose root holds the append-ordered entry list ({@code index ==
 * list position} — one invariant, trivially restart-stable). All mutations
 * are serialized through a single write lock; the storage tree is hardened
 * owner-only before the first byte is written (JS-SEC-037 — the chain
 * carries subject-attributable payloads).
 *
 * @since 00.80.00
 */
@ExperimentalJSentinelApi
public final class EclipseStoreAuditChainStorage implements AutoCloseable, HasLogger {

  private final EmbeddedStorageManager manager;
  private final AuditChainStorageRoot root;
  private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
  private boolean closed;

  private EclipseStoreAuditChainStorage(EmbeddedStorageManager manager,
      AuditChainStorageRoot root) {
    this.manager = manager;
    this.root = root;
  }

  /**
   * Opens (or creates) the chain storage below {@code storageDirectory}.
   *
   * @param storageDirectory the storage tree
   * @return the ready-to-use storage facade
   */
  public static EclipseStoreAuditChainStorage openAt(Path storageDirectory) {
    Objects.requireNonNull(storageDirectory, "storageDirectory");
    StorageTreeHardening.hardenOwnerOnly(storageDirectory,
        "audit-integrity-persistence/storage-permissions",
        "the store holds the tamper-evident audit hash chain");
    EmbeddedStorageManager manager = EmbeddedStorage.start(storageDirectory);
    AuditChainStorageRoot root;
    if (manager.root() instanceof AuditChainStorageRoot existing) {
      root = existing;
    } else {
      root = new AuditChainStorageRoot();
      manager.setRoot(root);
      manager.storeRoot();
    }
    return new EclipseStoreAuditChainStorage(manager, root);
  }

  /** @return the persistent {@link AuditChainStore} backed by this storage */
  public AuditChainStore chainStore() {
    return new EclipseStoreAuditChainStore(this);
  }

  EmbeddedStorageManager manager() {
    return manager;
  }

  AuditChainStorageRoot root() {
    return root;
  }

  ReentrantReadWriteLock lock() {
    return lock;
  }

  void requireOpen() {
    if (closed) {
      throw new IllegalStateException("the audit-chain storage is closed");
    }
  }

  /** Idempotent; ordered against in-flight writes via the write lock. */
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
