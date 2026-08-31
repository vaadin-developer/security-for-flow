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
package eu.jsentinel.jcustos.bootstrap;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("FileBootstrapTokenStore")
class FileBootstrapTokenStoreTest {

  @Test
  @DisplayName("JS-SEC-016: the saved token file is owner-only (0600) on POSIX")
  void savedFileIsOwnerOnly(@TempDir Path tmp) throws Exception {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        java.nio.file.FileSystems.getDefault().supportedFileAttributeViews().contains("posix"),
        "POSIX-only permission check");
    Path file = tmp.resolve("bootstrap.token");
    new FileBootstrapTokenStore(file)
        .save(new BootstrapToken("ABCD-EFGH-JKLM-NPQR-STUV", Instant.parse("2026-05-06T09:30:00Z")));
    Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file);
    assertEquals(Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE), perms,
        "the bootstrap token file must be owner-only rw------- (no group/other access)");
  }

  @Test
  @DisplayName("save writes token; load reads it back; invalidate deletes the file")
  void roundTrip(@TempDir Path tmp) {
    Path file = tmp.resolve("bootstrap.token");
    FileBootstrapTokenStore store = new FileBootstrapTokenStore(file);

    BootstrapToken original = new BootstrapToken("ABCD-EFGH-JKLM-NPQR-STUV", Instant.parse("2026-05-06T09:30:00Z"));
    store.save(original);

    assertTrue(Files.exists(file));
    Optional<BootstrapToken> loaded = store.load();
    assertTrue(loaded.isPresent());
    assertEquals(original.value(), loaded.get().value());
    assertEquals(original.createdAt(), loaded.get().createdAt());

    store.invalidate();
    assertFalse(Files.exists(file));
  }

  @Test
  @DisplayName("save creates parent directories if missing")
  void createsParentDirectories(@TempDir Path tmp) {
    Path file = tmp.resolve("nested/again/bootstrap.token");
    FileBootstrapTokenStore store = new FileBootstrapTokenStore(file);
    store.save(new BootstrapToken("ABCD-EFGH-JKLM-NPQR-STUV", Instant.now()));
    assertTrue(Files.exists(file));
  }

  @Test
  @DisplayName("save uses owner-only permissions on POSIX file systems")
  void posixPermissions(@TempDir Path tmp) throws Exception {
    Path file = tmp.resolve("bootstrap.token");
    FileBootstrapTokenStore store = new FileBootstrapTokenStore(file);
    store.save(new BootstrapToken("ABCD-EFGH-JKLM-NPQR-STUV", Instant.now()));

    if (!file.getFileSystem().supportedFileAttributeViews().contains("posix")) return;
    Set<PosixFilePermission> perms = Files.getPosixFilePermissions(file);
    assertTrue(perms.contains(PosixFilePermission.OWNER_READ));
    assertTrue(perms.contains(PosixFilePermission.OWNER_WRITE));
    assertFalse(perms.contains(PosixFilePermission.GROUP_READ));
    assertFalse(perms.contains(PosixFilePermission.OTHERS_READ));
  }

  @Test
  @DisplayName("load returns empty when no file exists")
  void loadEmpty(@TempDir Path tmp) {
    FileBootstrapTokenStore store = new FileBootstrapTokenStore(tmp.resolve("missing.token"));
    assertTrue(store.load().isEmpty());
  }
}
