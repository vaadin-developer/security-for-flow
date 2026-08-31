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

import java.nio.file.Path;
import java.time.Duration;
import java.util.Objects;

/**
 * Bootstrap configuration record.
 *
 * @param mode           mode of operation
 * @param tokenFilePath  token file path (required for {@link BootstrapMode#PERSISTENT_FILE})
 * @param tokenValidity  how long a generated token stays valid before it is
 *                       regenerated on startup and rejected by the service
 */
public record BootstrapConfiguration(BootstrapMode mode, Path tokenFilePath, Duration tokenValidity) {

  /** Default token lifetime — 24 hours. */
  public static final Duration DEFAULT_VALIDITY = Duration.ofHours(24);

  public BootstrapConfiguration {
    Objects.requireNonNull(mode, "mode must not be null");
    Objects.requireNonNull(tokenValidity, "tokenValidity must not be null");
    if (tokenValidity.isNegative() || tokenValidity.isZero()) {
      throw new IllegalArgumentException("tokenValidity must be positive");
    }
    if (mode == BootstrapMode.PERSISTENT_FILE && tokenFilePath == null) {
      throw new IllegalArgumentException("tokenFilePath required for PERSISTENT_FILE");
    }
  }

  public static BootstrapConfiguration disabled() {
    return new BootstrapConfiguration(BootstrapMode.DISABLED, null, DEFAULT_VALIDITY);
  }

  public static BootstrapConfiguration persistent(Path tokenFilePath) {
    return persistent(tokenFilePath, DEFAULT_VALIDITY);
  }

  public static BootstrapConfiguration persistent(Path tokenFilePath, Duration tokenValidity) {
    return new BootstrapConfiguration(BootstrapMode.PERSISTENT_FILE, tokenFilePath, tokenValidity);
  }

  public static BootstrapConfiguration transientConsole() {
    return transientConsole(DEFAULT_VALIDITY);
  }

  public static BootstrapConfiguration transientConsole(Duration tokenValidity) {
    return new BootstrapConfiguration(BootstrapMode.TRANSIENT_CONSOLE, null, tokenValidity);
  }
}
