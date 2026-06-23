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

import com.svenruppert.dependencies.core.logger.HasLogger;
import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.nio.file.Path;
import java.util.Objects;

/**
 * Linked-lifecycle handle around two Eclipse-Store storages opened at
 * the same parent directory: the framework storage (Phase-2 jSentinel
 * stores: audit, sessions, login attempts, role assignments,
 * remember-me / password-reset / email-verification tokens, API keys,
 * refresh tokens, rate limits, security version) and an application
 * storage that holds domain data the consuming app owns end-to-end.
 *
 * <p>The pair is opened together via {@link JSentinelStorageFactory}
 * and closed together via {@link #close()}, which runs a two-phase
 * shutdown (app first, framework second) and preserves the Phase-1
 * exception via {@link Throwable#addSuppressed(Throwable)} if Phase 2
 * also fails. See Konzept-V00.74.20 §6 for the validation and audit
 * code catalogue.
 *
 * <p>The Phase-1 / Phase-2 sequence guarantees that the framework
 * storage always gets a close-attempt, even when app shutdown throws.
 * The two-phase implementation lands in Prompt 006; this is the
 * Phase-1 (Public-API) skeleton record.
 *
 * @param framework Eclipse-Store-backed framework storage facade
 *                  carrying the 13 Phase-2 stores
 * @param app       Eclipse-Store storage manager holding the
 *                  application's domain data — the consumer accesses
 *                  it directly via {@code app.root()}
 * @param parent    parent directory the pair was opened under
 * @param layout    {@link StorageLayout} that determined the on-disk
 *                  sub-directory names
 * @since 00.74.20
 */
@ExperimentalJSentinelApi
public record JSentinelStoragePair(
    EclipseStoreJSentinelStorage framework,
    EmbeddedStorageManager       app,
    Path                         parent,
    StorageLayout                layout)
    implements AutoCloseable, HasLogger {

  public JSentinelStoragePair {
    Objects.requireNonNull(framework, "framework");
    Objects.requireNonNull(app, "app");
    Objects.requireNonNull(parent, "parent");
    Objects.requireNonNull(layout, "layout");
  }

  /**
   * Two-phase close: app storage first, framework storage second.
   * Phase 2 always runs even if Phase 1 throws; secondary failures
   * are added as suppressed exceptions to the primary. Idempotency
   * (flag-guarded) is added in Prompt 006 together with the real
   * implementation.
   */
  @Override
  public void close() {
    throw new UnsupportedOperationException(
        "implemented in Prompt 006 (V00.74.20 Phase 3)");
  }
}
