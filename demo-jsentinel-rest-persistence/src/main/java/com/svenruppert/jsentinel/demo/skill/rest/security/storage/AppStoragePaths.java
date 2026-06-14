/*
 * Copyright © 2013 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 (the "Licence");
 * you may not use this file except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 *     https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */

package com.svenruppert.jsentinel.demo.skill.rest.security.storage;

import java.nio.file.Path;

/**
 * Single source of truth for the application's on-disk storage paths.
 *
 * <p>Production runs use {@code ./data/jsentinel-rest-persistence} as the base. Tests,
 * CI and any deployment that wants to redirect persistence elsewhere
 * override the base via the JVM system property
 * {@code -Dapp.storage.dir=/some/path}.
 *
 * <p>Three derived locations:
 * <ul>
 *   <li>{@link #frameworkStorageDir()} — jSentinel framework storage
 *       (audit log + session store).</li>
 *   <li>{@link #userDirectoryDir()} — the application's user
 *       directory (Eclipse-Store-backed).</li>
 *   <li>{@link #bootstrapTokenFile()} — the one-time bootstrap token
 *       written by {@code BootstrapStartup} on first start.</li>
 * </ul>
 *
 * <p>This file is deliberately tiny — keeping path policy in one
 * place avoids drift when redirecting storage at runtime. Wire
 * Surefire so tests fork with
 * {@code app.storage.dir = ${project.build.directory}/test-data}:
 *
 * <pre>
 * &lt;plugin&gt;
 *   &lt;artifactId&gt;maven-surefire-plugin&lt;/artifactId&gt;
 *   &lt;configuration&gt;
 *     &lt;systemPropertyVariables&gt;
 *       &lt;app.storage.dir&gt;${project.build.directory}/test-data&lt;/app.storage.dir&gt;
 *     &lt;/systemPropertyVariables&gt;
 *   &lt;/configuration&gt;
 * &lt;/plugin&gt;
 * </pre>
 *
 * <p>That way no test run ever creates the repo-rooted
 * {@code ./data/jsentinel-rest-persistence} directory, and PIT workers cannot corrupt
 * each other's storage state.
 */
public final class AppStoragePaths {

  /** System-property name for the storage base directory. */
  public static final String PROPERTY = "app.storage.dir";

  /** Built-in default when nothing was configured. */
  public static final String DEFAULT = "./data/jsentinel-rest-persistence";

  private AppStoragePaths() {
  }

  /** Base directory for all app-owned storage. */
  public static Path baseDir() {
    return Path.of(System.getProperty(PROPERTY, DEFAULT));
  }

  /** jSentinel framework storage — audit + session stores. */
  public static Path frameworkStorageDir() {
    return baseDir().resolve("jsentinel");
  }

  /** Application user directory — {@code User} map. */
  public static Path userDirectoryDir() {
    return baseDir().resolve("app").resolve("users");
  }

  /** Bootstrap token file written on first start. */
  public static Path bootstrapTokenFile() {
    return frameworkStorageDir().resolve("bootstrap.token");
  }
}
