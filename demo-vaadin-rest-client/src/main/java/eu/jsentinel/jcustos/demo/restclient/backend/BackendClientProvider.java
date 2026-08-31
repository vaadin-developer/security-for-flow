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
package eu.jsentinel.jcustos.demo.restclient.backend;

import java.util.Objects;

/**
 * Static accessor for the singleton {@link DemoBackendClient}. Required
 * because the SPI-loaded authorization adapters
 * ({@code RestBackedAuthenticationService}, {@code BackedLoginListener})
 * have no DI surface to receive the client.
 * <p>
 * Tests replace the client via {@link #setClient(DemoBackendClient)} and
 * restore the production wiring with {@link #reset()}.
 */
public final class BackendClientProvider {

  private static volatile DemoBackendClient current =
      new HttpDemoBackendClient(BackendConfig.fromEnvironment());

  private BackendClientProvider() {
  }

  public static DemoBackendClient client() {
    return current;
  }

  /** Test seam — replace the client. */
  public static void setClient(DemoBackendClient replacement) {
    current = Objects.requireNonNull(replacement, "replacement");
  }

  /** Test seam — restore the default HTTP-backed client built from env config. */
  public static void reset() {
    current = new HttpDemoBackendClient(BackendConfig.fromEnvironment());
  }
}
