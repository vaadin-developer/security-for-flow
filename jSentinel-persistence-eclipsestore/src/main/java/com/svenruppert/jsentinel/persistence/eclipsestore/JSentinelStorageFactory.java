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
package com.svenruppert.jsentinel.persistence.eclipsestore;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import org.eclipse.store.storage.embedded.types.EmbeddedStorage;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Entry point for opening a {@link JSentinelStoragePair} — the
 * Phase-1-Public-API of the V00.74.20 Storage-Pair architecture.
 *
 * <p>Consumers open a pair once at process startup and close it once
 * at shutdown:
 *
 * <pre>{@code
 * try (var pair = JSentinelStorageFactory.openAt(Path.of("/var/data/myapp"))) {
 *   VaadinSecurity.bootstrap()
 *       .audit(a -> a.storeBacked(pair.framework().auditEventStore()))
 *       .sessions(s -> s.storeBacked(pair.framework().sessionStore()))
 *       .install();
 *   // Use pair.app() for domain data via app.root()
 * }
 * }</pre>
 *
 * <p>The {@code openAt(Path)} overload defaults to
 * {@link StorageLayout#DEFAULT}. Consumers who need a non-default
 * sub-directory layout (e.g. {@code new StorageLayout(".", "users")}
 * to retain the V00.70 single-storage layout) pass the explicit
 * overload.
 *
 * <p>This Phase-1 skeleton throws {@link UnsupportedOperationException}
 * from the two-arg overload; the real implementation lands in
 * Prompt 005 of the V00.74.20 plan.
 *
 * @since 00.74.20
 */
@ExperimentalJSentinelApi
public final class JSentinelStorageFactory {

  private JSentinelStorageFactory() {
    // utility class — never instantiated
  }

  /**
   * Opens a storage pair under {@code parent} using
   * {@link StorageLayout#DEFAULT}.
   *
   * @param parent parent directory under which the framework and app
   *               sub-directories will be created or read
   * @return a freshly opened {@link JSentinelStoragePair}
   * @throws NullPointerException     if {@code parent} is {@code null}
   * @throws IllegalArgumentException with one of the Konzept §6
   *                                  validation codes if {@code parent}
   *                                  exists and is not a writable
   *                                  directory
   */
  public static JSentinelStoragePair openAt(Path parent) {
    return openAt(parent, StorageLayout.DEFAULT);
  }

  /**
   * Opens a storage pair under {@code parent} using the supplied
   * {@code layout}.
   *
   * @param parent parent directory under which the framework and app
   *               sub-directories will be created or read
   * @param layout sub-directory layout to use
   * @return a freshly opened {@link JSentinelStoragePair}
   * @throws NullPointerException     if either argument is {@code null}
   * @throws IllegalArgumentException with one of the Konzept §6
   *                                  validation codes if {@code parent}
   *                                  exists and is not a writable
   *                                  directory
   */
  public static JSentinelStoragePair openAt(Path parent, StorageLayout layout) {
    Objects.requireNonNull(parent, "parent");
    Objects.requireNonNull(layout, "layout");
    ensureParentIsWritableDirectory(parent);

    Path frameworkDir = parent.resolve(layout.frameworkSubdir());
    Path appDir       = parent.resolve(layout.appSubdir());

    EmbeddedStorageManager frameworkMgr = null;
    EmbeddedStorageManager appMgr       = null;
    try {
      frameworkMgr = EclipseStoreJSentinelStorage.initStorageManager(frameworkDir);
      appMgr       = EmbeddedStorage.start(appDir);
      return new JSentinelStoragePair(
          new EclipseStoreJSentinelStorage(frameworkMgr),
          appMgr,
          parent,
          layout,
          new AtomicBoolean(false));
    } catch (RuntimeException openFailure) {
      // Roll back any half-opened manager. The original failure is the
      // one consumers care about; secondary shutdown failures get
      // swallowed by safelyShutdown so they cannot mask the primary.
      safelyShutdown(appMgr);
      safelyShutdown(frameworkMgr);
      throw openFailure;
    }
  }

  /**
   * Validates that {@code parent} either does not yet exist (then the
   * Eclipse-Store {@code start(dir)} call will create it) or, if it
   * exists, is a writable directory. Carries the Konzept §6 codes
   * {@code persistence/storage-pair-parent-not-directory} and
   * {@code persistence/storage-pair-parent-not-writable} in the
   * IllegalArgumentException message.
   */
  private static void ensureParentIsWritableDirectory(Path parent) {
    if (!Files.exists(parent)) {
      return; // EmbeddedStorage.start will create it
    }
    if (!Files.isDirectory(parent)) {
      throw new IllegalArgumentException(
          "persistence/storage-pair-parent-not-directory: " + parent);
    }
    if (!Files.isWritable(parent)) {
      throw new IllegalArgumentException(
          "persistence/storage-pair-parent-not-writable: " + parent);
    }
  }

  /**
   * Best-effort shutdown of a possibly-null storage manager during
   * roll-back. Secondary failures are swallowed because the original
   * open-failure is what the caller needs to see.
   */
  private static void safelyShutdown(EmbeddedStorageManager mgr) {
    if (mgr == null) return;
    try {
      mgr.shutdown();
    } catch (RuntimeException secondary) {
      // Swallow — primary openFailure is rethrown by the caller.
    }
  }
}
