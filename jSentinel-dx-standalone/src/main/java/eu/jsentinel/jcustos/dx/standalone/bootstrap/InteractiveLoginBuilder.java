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

import java.util.Objects;

/**
 * Fluent sub-builder for {@link InteractiveLoginConfiguration}.
 * Created via
 * {@code StandaloneJSentinelBootstrap.interactiveLogin(consumer)}.
 *
 * <pre>
 *   StandaloneSecurity.bootstrap()
 *       .interactiveLogin(l -> l
 *           .prompt(consoleLoginPrompt())
 *           .maxAttempts(3))
 *       .install();
 * </pre>
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public final class InteractiveLoginBuilder {

  private InteractiveLoginPrompt prompt;
  private int maxAttempts;

  InteractiveLoginBuilder() {
  }

  /**
   * Sets the prompt callback.
   *
   * @param prompt non-null callback
   * @return this builder
   */
  public InteractiveLoginBuilder prompt(InteractiveLoginPrompt prompt) {
    this.prompt = Objects.requireNonNull(prompt, "prompt");
    return this;
  }

  /**
   * Sets the maximum attempts (0 = unlimited).
   *
   * @param attempts non-negative attempt cap
   * @return this builder
   */
  public InteractiveLoginBuilder maxAttempts(int attempts) {
    if (attempts < 0) {
      throw new IllegalArgumentException("maxAttempts must be >= 0");
    }
    this.maxAttempts = attempts;
    return this;
  }

  InteractiveLoginConfiguration toConfiguration() {
    if (prompt == null) {
      throw new IllegalStateException(
          "interactiveLogin requires .prompt(...) before install()");
    }
    return new InteractiveLoginConfiguration(prompt, maxAttempts);
  }
}
