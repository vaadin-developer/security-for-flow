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
package com.svenruppert.jsentinel.events.persistence.eclipsestore;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

@DisplayName("EclipseStoreEventStorage — JS-SEC-037 owner-only storage tree")
class EclipseStoreEventStoragePermissionsTest {

  @Test
  @DisplayName("openAt creates the event-store directory owner-only (0700) on POSIX")
  void openAtCreatesOwnerOnlyDir(@TempDir Path base) throws IOException {
    assumeTrue(base.getFileSystem().supportedFileAttributeViews().contains("posix"),
        "POSIX file system required");
    // a NON-existent subdir — openAt must create it 0700 (a pre-existing @TempDir keeps
    // its default umask perms, so we point at a path openAt has to create itself).
    Path store = base.resolve("event-store");
    try (EclipseStoreEventStorage storage = EclipseStoreEventStorage.openAt(store)) {
      Set<PosixFilePermission> perms = Files.getPosixFilePermissions(store);
      assertFalse(
          perms.stream().anyMatch(p -> p.name().startsWith("GROUP_") || p.name().startsWith("OTHERS_")),
          "event-store dir must be owner-only, was " + PosixFilePermissions.toString(perms));
    }
  }
}
