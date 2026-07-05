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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * Single home for the POSIX owner-only ({@code 0700}) hardening of an Eclipse-Store
 * storage directory (JS-SEC-017 / JS-SEC-037 / JS-SEC-038, CWE-276).
 *
 * <p>RF (exit-review, reuse): three byte-identical copies of this hardening previously
 * lived in {@link JSentinelStorageFactory} (as {@code hardenStorageTree} /
 * {@code createOwnerOnly} / {@code warnIfGroupOrOtherAccessible}),
 * {@link EclipseStoreJSentinelStorage} and the events module's
 * {@code EclipseStoreEventStorage}. Duplicated security-critical code drifts — the next
 * permission-policy change would land in one copy and silently miss the others (exactly the
 * JS-SEC-017 → JS-SEC-038 regression class this line already had to patch twice). All three
 * now call this helper. Because the events persistence module depends on this one, the type is
 * {@code public} so it can be shared across package boundaries.
 *
 * @since 00.79.40
 */
@ExperimentalJSentinelApi
public final class StorageTreeHardening {

  private StorageTreeHardening() {
    // utility class — never instantiated
  }

  /**
   * Pre-creates {@code dir} owner-only ({@code 0700}) on POSIX before Eclipse-Store opens
   * it, so the store is never group/other-readable under a default umask, and warns if an
   * already-existing tree is group/other-accessible. Best-effort: never blocks the open, and
   * a no-op on non-POSIX filesystems (which rely on directory ACLs instead).
   *
   * @param dir             storage directory to harden; created if missing
   * @param logPrefix       stable log/audit code prefix for the warning
   *                        (e.g. {@code "persistence/storage-permissions"})
   * @param storeDescription short human phrase naming what the store holds, appended to the
   *                        exposure warning (e.g. "the framework store holds session handles,
   *                        roles and token hashes")
   */
  public static void hardenOwnerOnly(Path dir, String logPrefix, String storeDescription) {
    if (!dir.getFileSystem().supportedFileAttributeViews().contains("posix")) {
      return;
    }
    try {
      if (!Files.exists(dir)) {
        Files.createDirectories(dir, PosixFilePermissions.asFileAttribute(
            PosixFilePermissions.fromString("rwx------")));
      }
      Set<PosixFilePermission> perms = Files.getPosixFilePermissions(dir);
      if (perms.stream().anyMatch(
          p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_"))) {
        HasLogger.staticLogger().warn(
            "{}: {} is group/other-accessible ({}); {}",
            logPrefix, dir, PosixFilePermissions.toString(perms), storeDescription);
      }
    } catch (IOException hardenFailure) {
      HasLogger.staticLogger().warn(
          "{}: could not harden {} to owner-only: {}",
          logPrefix, dir, hardenFailure.toString());
    }
  }
}
