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


/**
 * Immutable snapshot of the standalone thread-propagation
 * configuration collected via
 * {@code StandaloneJCustosBootstrap.threadPropagation(consumer)}.
 *
 * @param mode propagation mode; non-null
 *
 * @since 00.74.00
 */
public record ThreadPropagationStrategy(ThreadPropagationMode mode) {

  /** Validates mode is non-null. */
  public ThreadPropagationStrategy {
    if (mode == null) {
      throw new IllegalArgumentException("mode must not be null");
    }
  }
}
