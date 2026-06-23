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

import java.util.Objects;

/**
 * Names of the two sub-directories a {@code JSentinelStoragePair} lays
 * out under a single parent directory: one for the framework storage
 * (Phase-2 stores: audit, sessions, login attempts, etc.) and one for
 * application domain data.
 *
 * <p>The default layout (created via {@link #DEFAULT}) places the
 * framework data under {@code jsentinel-store/} and the application
 * data under {@code app-store/}. Consumers who already operate on a
 * V00.70 layout can opt into a legacy layout, e.g.
 * {@code new StorageLayout(".", "users")} to keep the framework data
 * at the parent directory itself and place application data alongside.
 *
 * <p>The compact constructor rejects {@code null} / blank names, names
 * containing path separators ({@code /}, {@code \}) or NUL bytes, and
 * the case where the framework and app sub-directories would collide.
 * The collision case is reported via the Konzept §6 code
 * {@code persistence/storage-pair-subdir-collision} embedded in the
 * exception message.
 *
 * @param frameworkSubdir name of the framework-storage sub-directory
 *                        relative to the storage pair's parent
 * @param appSubdir       name of the application-storage sub-directory
 *                        relative to the storage pair's parent
 * @since 00.74.20
 */
@ExperimentalJSentinelApi
public record StorageLayout(String frameworkSubdir, String appSubdir) {

  /**
   * Default layout placing framework data under {@code jsentinel-store/}
   * and application data under {@code app-store/}.
   */
  public static final StorageLayout DEFAULT =
      new StorageLayout("jsentinel-store", "app-store");

  public StorageLayout {
    requireValidSubdirName(frameworkSubdir, "frameworkSubdir");
    requireValidSubdirName(appSubdir, "appSubdir");
    if (frameworkSubdir.equals(appSubdir)) {
      throw new IllegalArgumentException(
          "persistence/storage-pair-subdir-collision: "
              + "framework and app subdir must differ (both = '"
              + frameworkSubdir + "')");
    }
  }

  private static void requireValidSubdirName(String name, String label) {
    Objects.requireNonNull(name, label);
    if (name.isBlank()) {
      throw new IllegalArgumentException(label + " must not be blank");
    }
    if (name.indexOf('/') >= 0
        || name.indexOf('\\') >= 0
        || name.indexOf('\0') >= 0) {
      throw new IllegalArgumentException(
          label + " must not contain path separators or NUL");
    }
  }
}
