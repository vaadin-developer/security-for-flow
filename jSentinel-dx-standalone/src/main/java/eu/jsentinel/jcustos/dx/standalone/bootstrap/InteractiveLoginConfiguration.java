/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
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
package eu.jsentinel.jcustos.dx.standalone.bootstrap;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

/**
 * Immutable snapshot of the interactive-login configuration
 * collected via
 * {@code StandaloneJSentinelBootstrap.interactiveLogin(consumer)}.
 *
 * @param prompt      the prompt callback; non-null
 * @param maxAttempts max attempts before the loop should give up;
 *                    {@code 0} means unlimited
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public record InteractiveLoginConfiguration(
    InteractiveLoginPrompt prompt,
    int maxAttempts
) {

  /** Validates {@code prompt} and {@code maxAttempts}. */
  public InteractiveLoginConfiguration {
    if (prompt == null) {
      throw new IllegalArgumentException("prompt must not be null");
    }
    if (maxAttempts < 0) {
      throw new IllegalArgumentException("maxAttempts must be >= 0");
    }
  }
}
