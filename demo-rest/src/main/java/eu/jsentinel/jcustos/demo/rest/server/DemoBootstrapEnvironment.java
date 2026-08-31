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
package eu.jsentinel.jcustos.demo.rest.server;

import eu.jsentinel.jcustos.bootstrap.BootstrapConfiguration;
import eu.jsentinel.jcustos.bootstrap.BootstrapConfigurationLoader;
import eu.jsentinel.jcustos.bootstrap.BootstrapMode;

import java.nio.file.Path;

/**
 * Demo-side defaults for the bootstrap configuration. The actual reading of
 * system properties and environment variables happens in
 * {@link BootstrapConfigurationLoader} (security-core).
 * <p>
 * Default for the demo is {@link BootstrapMode#TRANSIENT_CONSOLE} so the demo
 * "just works" when no administrator is provisioned. Override via
 * {@code security.bootstrap.mode} / {@code SECURITY_BOOTSTRAP_MODE}.
 */
public final class DemoBootstrapEnvironment {

  public static final BootstrapMode DEFAULT_MODE = BootstrapMode.TRANSIENT_CONSOLE;
  public static final Path DEFAULT_TOKEN_FILE = Path.of("./data/bootstrap.token");

  private DemoBootstrapEnvironment() {
  }

  public static BootstrapConfiguration fromEnvironment() {
    return new BootstrapConfigurationLoader().load(
        DEFAULT_MODE,
        DEFAULT_TOKEN_FILE,
        BootstrapConfiguration.DEFAULT_VALIDITY);
  }
}
