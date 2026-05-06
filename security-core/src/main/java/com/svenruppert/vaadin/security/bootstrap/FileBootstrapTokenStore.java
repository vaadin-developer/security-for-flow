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
package com.svenruppert.vaadin.security.bootstrap;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;

/**
 * File-backed token store for {@link BootstrapMode#PERSISTENT_FILE}.
 * <p>
 * The token survives restarts as long as the file exists. POSIX systems
 * receive {@code rw-------} (0600) permissions on save.
 * <p>
 * Format (intentionally simple, no JSON dependency):
 * <pre>
 * token=XXXX-XXXX-XXXX-XXXX-XXXX
 * createdAt=2026-05-06T09:30:00Z
 * </pre>
 */
public final class FileBootstrapTokenStore implements BootstrapTokenStore {

  private static final EnumSet<PosixFilePermission> OWNER_RW =
      EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE);

  private final Path path;

  public FileBootstrapTokenStore(Path path) {
    this.path = path;
  }

  @Override
  public Optional<BootstrapToken> load() {
    if (!Files.exists(path)) return Optional.empty();
    try {
      List<String> lines = Files.readAllLines(path);
      String tokenValue = null;
      Instant createdAt = null;
      for (String line : lines) {
        String trimmed = line.trim();
        if (trimmed.startsWith("token=")) {
          tokenValue = trimmed.substring("token=".length()).trim();
        } else if (trimmed.startsWith("createdAt=")) {
          try {
            createdAt = Instant.parse(trimmed.substring("createdAt=".length()).trim());
          } catch (DateTimeParseException ignored) {
            // fall through — corrupt file
          }
        }
      }
      if (tokenValue == null || tokenValue.isBlank() || createdAt == null) {
        return Optional.empty();
      }
      return Optional.of(new BootstrapToken(tokenValue, createdAt));
    } catch (IOException e) {
      return Optional.empty();
    }
  }

  @Override
  public void save(BootstrapToken token) {
    try {
      Path parent = path.toAbsolutePath().getParent();
      if (parent != null) Files.createDirectories(parent);
      String content =
          "token=" + token.value() + System.lineSeparator()
              + "createdAt=" + token.createdAt() + System.lineSeparator();
      Files.writeString(path, content);
      tightenPermissions(path);
    } catch (IOException e) {
      throw new IllegalStateException("Could not write bootstrap token file", e);
    }
  }

  @Override
  public void invalidate() {
    try {
      Files.deleteIfExists(path);
    } catch (IOException e) {
      throw new IllegalStateException("Could not delete bootstrap token file", e);
    }
  }

  public Path path() {
    return path;
  }

  private static void tightenPermissions(Path path) {
    if (!path.getFileSystem().supportedFileAttributeViews().contains("posix")) return;
    try {
      Files.setPosixFilePermissions(path, PosixFilePermissions.asFileAttribute(OWNER_RW).value());
    } catch (IOException | UnsupportedOperationException ignored) {
      // best effort — non-POSIX platforms skip silently
    }
  }
}
