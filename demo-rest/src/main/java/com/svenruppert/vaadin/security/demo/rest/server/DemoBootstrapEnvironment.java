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
package com.svenruppert.vaadin.security.demo.rest.server;

import com.svenruppert.vaadin.security.bootstrap.BootstrapConfiguration;
import com.svenruppert.vaadin.security.bootstrap.BootstrapMode;

import java.nio.file.Path;

/**
 * Reads the bootstrap configuration from system properties (preferred) and
 * environment variables (fallback). Defaults to {@link BootstrapMode#TRANSIENT_CONSOLE}
 * so the demo "just works" when no administrator is provisioned.
 *
 * <ul>
 *   <li>Sysprop {@code security.bootstrap.mode} or env {@code SECURITY_BOOTSTRAP_MODE}
 *       — {@code DISABLED} / {@code TRANSIENT_CONSOLE} / {@code PERSISTENT_FILE}</li>
 *   <li>Sysprop {@code security.bootstrap.token.file} or env
 *       {@code SECURITY_BOOTSTRAP_TOKEN_FILE} — used in {@code PERSISTENT_FILE} mode
 *       (default {@code ./data/bootstrap.token})</li>
 * </ul>
 */
public final class DemoBootstrapEnvironment {

  public static final String MODE_PROPERTY = "security.bootstrap.mode";
  public static final String MODE_ENV = "SECURITY_BOOTSTRAP_MODE";
  public static final String TOKEN_FILE_PROPERTY = "security.bootstrap.token.file";
  public static final String TOKEN_FILE_ENV = "SECURITY_BOOTSTRAP_TOKEN_FILE";
  public static final String DEFAULT_TOKEN_FILE = "./data/bootstrap.token";

  private DemoBootstrapEnvironment() {
  }

  public static BootstrapConfiguration fromEnvironment() {
    String modeValue = firstNonBlank(
        System.getProperty(MODE_PROPERTY),
        System.getenv(MODE_ENV));
    if (modeValue == null) modeValue = "TRANSIENT_CONSOLE";
    BootstrapMode mode;
    try {
      mode = BootstrapMode.valueOf(modeValue.trim().toUpperCase());
    } catch (IllegalArgumentException e) {
      mode = BootstrapMode.TRANSIENT_CONSOLE;
    }
    return switch (mode) {
      case DISABLED -> BootstrapConfiguration.disabled();
      case TRANSIENT_CONSOLE -> BootstrapConfiguration.transientConsole();
      case PERSISTENT_FILE -> {
        String pathValue = firstNonBlank(
            System.getProperty(TOKEN_FILE_PROPERTY),
            System.getenv(TOKEN_FILE_ENV));
        if (pathValue == null) pathValue = DEFAULT_TOKEN_FILE;
        yield BootstrapConfiguration.persistent(Path.of(pathValue));
      }
    };
  }

  /** @deprecated Renamed; use {@link #fromEnvironment()}. */
  @Deprecated
  public static BootstrapConfiguration fromSystemProperties() {
    return fromEnvironment();
  }

  private static String firstNonBlank(String a, String b) {
    if (a != null && !a.isBlank()) return a;
    if (b != null && !b.isBlank()) return b;
    return null;
  }
}
