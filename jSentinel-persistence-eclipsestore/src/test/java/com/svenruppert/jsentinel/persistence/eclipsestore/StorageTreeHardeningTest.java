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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * RF (exit-review): the POSIX owner-only hardening now has a single home,
 * {@link StorageTreeHardening}, reused by the framework facade, the storage factory and the
 * events persistence module (was three byte-identical copies). Pins the shared behaviour so
 * a future permission-policy change lands in exactly one place.
 */
@DisplayName("StorageTreeHardening (RF)")
class StorageTreeHardeningTest {

  @Test
  @DisplayName("creates a missing directory owner-only (0700) on POSIX")
  void createsOwnerOnlyDirectory(@TempDir Path base) throws Exception {
    assumeTrue(base.getFileSystem().supportedFileAttributeViews().contains("posix"),
        "owner-only hardening only applies on POSIX filesystems");
    Path store = base.resolve("framework-store");

    StorageTreeHardening.hardenOwnerOnly(store, "persistence/storage-permissions",
        "the framework store holds session handles, roles and token hashes");

    assertEquals(PosixFilePermissions.fromString("rwx------"),
        Files.getPosixFilePermissions(store),
        "the freshly created storage directory must be owner-only");
  }
}
