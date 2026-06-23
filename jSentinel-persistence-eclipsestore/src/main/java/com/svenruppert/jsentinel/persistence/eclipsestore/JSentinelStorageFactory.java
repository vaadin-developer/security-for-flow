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

import java.nio.file.Path;
import java.util.Objects;

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
    throw new UnsupportedOperationException(
        "implemented in Prompt 005 (V00.74.20 Phase 2)");
  }
}
