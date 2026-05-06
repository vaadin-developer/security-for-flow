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

import java.nio.file.Path;
import java.util.Objects;

/**
 * Bootstrap configuration record.
 *
 * @param mode          mode of operation
 * @param tokenFilePath token file path (required for {@link BootstrapMode#PERSISTENT_FILE}).
 */
public record BootstrapConfiguration(BootstrapMode mode, Path tokenFilePath) {

  public BootstrapConfiguration {
    Objects.requireNonNull(mode, "mode must not be null");
    if (mode == BootstrapMode.PERSISTENT_FILE && tokenFilePath == null) {
      throw new IllegalArgumentException("tokenFilePath required for PERSISTENT_FILE");
    }
  }

  public static BootstrapConfiguration disabled() {
    return new BootstrapConfiguration(BootstrapMode.DISABLED, null);
  }

  public static BootstrapConfiguration persistent(Path tokenFilePath) {
    return new BootstrapConfiguration(BootstrapMode.PERSISTENT_FILE, tokenFilePath);
  }

  public static BootstrapConfiguration transientConsole() {
    return new BootstrapConfiguration(BootstrapMode.TRANSIENT_CONSOLE, null);
  }
}
