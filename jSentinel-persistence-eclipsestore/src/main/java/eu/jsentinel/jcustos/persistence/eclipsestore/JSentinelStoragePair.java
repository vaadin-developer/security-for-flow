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

import com.svenruppert.dependencies.core.logger.HasLogger;
import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;
import org.eclipse.store.storage.embedded.types.EmbeddedStorageManager;

import java.nio.file.Path;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicBoolean;

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
 * shutdown:
 *
 * <ol>
 *   <li><strong>Phase 1</strong> — shuts the app storage down. A
 *       failure here is captured but does not abort Phase 2.</li>
 *   <li><strong>Phase 2</strong> — closes the framework storage. This
 *       phase <em>always</em> runs, even if Phase 1 failed. If
 *       Phase 2 also fails while Phase 1 already had, the Phase-2
 *       exception is added as a suppressed exception to the Phase-1
 *       throwable.</li>
 * </ol>
 *
 * <p>The invariant — "Phase 2 always runs" — exists so the framework
 * storage's lock file is released even when the app's shutdown logic
 * misbehaves. Without it a buggy app could leave the framework data
 * inaccessible until the JVM exits.
 *
 * <p>{@code close()} is <strong>idempotent</strong>: a second call is
 * a no-op (Konzept §6 code {@code persistence/storage-pair-double-close},
 * INFO log). The flag-guard exists because consumers may install
 * close-hooks from multiple lifecycle sources (Vaadin
 * destroy-listener + JVM shutdown hook) and we cannot assume only one
 * fires.
 *
 * <p>Konzept §6 codes emitted by this class:
 * <ul>
 *   <li>{@code persistence/storage-pair-app-shutdown-failed} —
 *       Phase 1 threw (WARN log + re-throw at end).</li>
 *   <li>{@code persistence/storage-pair-framework-close-failed} —
 *       Phase 2 threw (WARN log + addSuppressed if Phase 1 also
 *       threw, otherwise re-throw).</li>
 *   <li>{@code persistence/storage-pair-double-close} —
 *       repeated close() call (INFO log, no-op).</li>
 * </ul>
 *
 * <p>The {@code closedFlag} component is an implementation detail —
 * the {@link JSentinelStorageFactory} always passes
 * {@code new AtomicBoolean(false)}. Consumers should not construct
 * instances by hand.
 *
 * @param framework   Eclipse-Store-backed framework storage facade
 *                    carrying the 13 Phase-2 stores
 * @param app         Eclipse-Store storage manager holding the
 *                    application's domain data — the consumer
 *                    accesses it directly via {@code app.root()}
 * @param parent      parent directory the pair was opened under
 * @param layout      {@link StorageLayout} that determined the
 *                    on-disk sub-directory names
 * @param closedFlag  internal idempotency guard; do not construct
 *                    manually — use {@link JSentinelStorageFactory}
 * @since 00.74.20
 */
@ExperimentalJSentinelApi
public record JSentinelStoragePair(
    EclipseStoreJSentinelStorage framework,
    EmbeddedStorageManager       app,
    Path                         parent,
    StorageLayout                layout,
    AtomicBoolean                closedFlag)
    implements AutoCloseable, HasLogger {

  public JSentinelStoragePair {
    Objects.requireNonNull(framework, "framework");
    Objects.requireNonNull(app, "app");
    Objects.requireNonNull(parent, "parent");
    Objects.requireNonNull(layout, "layout");
    Objects.requireNonNull(closedFlag, "closedFlag");
  }

  /**
   * Two-phase close: app storage first, framework storage second.
   * Phase 2 always runs even if Phase 1 throws; secondary failures
   * are added as suppressed exceptions to the primary. Second and
   * subsequent calls are no-ops (Konzept §6
   * {@code persistence/storage-pair-double-close}, INFO).
   */
  @Override
  public void close() {
    if (!closedFlag.compareAndSet(false, true)) {
      logger().info(
          "persistence/storage-pair-double-close: ignoring repeated close on {}",
          parent);
      return;
    }
    RuntimeException phase1Failure = null;
    try {
      app.shutdown();
    } catch (RuntimeException e) {
      logger().warn("persistence/storage-pair-app-shutdown-failed at {}",
          parent, e);
      phase1Failure = e;
    }
    try {
      framework.close();
    } catch (RuntimeException e) {
      logger().warn("persistence/storage-pair-framework-close-failed at {}",
          parent, e);
      if (phase1Failure != null) {
        phase1Failure.addSuppressed(e);
      } else {
        throw e;
      }
    }
    if (phase1Failure != null) {
      throw phase1Failure;
    }
  }
}
