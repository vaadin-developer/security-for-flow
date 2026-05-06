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
 * Reads the bootstrap configuration from system properties / environment
 * variables. Defaults to {@link BootstrapMode#DISABLED} so the existing
 * demo flows keep working.
 *
 * <ul>
 *   <li>{@code security.bootstrap.mode} = {@code DISABLED} (default) /
 *       {@code TRANSIENT_CONSOLE} / {@code PERSISTENT_FILE}</li>
 *   <li>{@code security.bootstrap.token.file} =
 *       {@code ./data/bootstrap.token} (used in {@code PERSISTENT_FILE}
 *       mode)</li>
 * </ul>
 */
public final class DemoBootstrapEnvironment {

  public static final String MODE_PROPERTY = "security.bootstrap.mode";
  public static final String TOKEN_FILE_PROPERTY = "security.bootstrap.token.file";
  public static final String DEFAULT_TOKEN_FILE = "./data/bootstrap.token";

  private DemoBootstrapEnvironment() {
  }

  public static BootstrapConfiguration fromSystemProperties() {
    String modeValue = System.getProperty(MODE_PROPERTY);
    if (modeValue == null || modeValue.isBlank()) modeValue = "DISABLED";
    BootstrapMode mode;
    try {
      mode = BootstrapMode.valueOf(modeValue.trim().toUpperCase());
    } catch (IllegalArgumentException e) {
      mode = BootstrapMode.DISABLED;
    }
    return switch (mode) {
      case DISABLED -> BootstrapConfiguration.disabled();
      case TRANSIENT_CONSOLE -> BootstrapConfiguration.transientConsole();
      case PERSISTENT_FILE -> {
        String pathValue = System.getProperty(TOKEN_FILE_PROPERTY, DEFAULT_TOKEN_FILE);
        yield BootstrapConfiguration.persistent(Path.of(pathValue));
      }
    };
  }
}
