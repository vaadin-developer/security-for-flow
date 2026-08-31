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
 * Fluent sub-builder for {@link ThreadPropagationStrategy}. Created
 * via {@code StandaloneJSentinelBootstrap.threadPropagation(consumer)}.
 *
 * <pre>
 *   StandaloneSecurity.bootstrap()
 *       .threadPropagation(t -> t.inheritOnSubmit())
 *       .install();
 *
 *   // later, in app code:
 *   Executor wrapped = StandaloneThreadPropagationContext.wrap(executor);
 *   wrapped.execute(() -> /* runs with the caller's subject bound *&#47;);
 * </pre>
 *
 * @since 00.74.00
 */
@ExperimentalJSentinelApi
public final class ThreadPropagationBuilder {

  private ThreadPropagationMode mode = ThreadPropagationMode.NONE;

  ThreadPropagationBuilder() {
  }

  /**
   * Selects {@link ThreadPropagationMode#INHERIT_ON_SUBMIT}. When
   * the consumer wraps an {@code Executor} via
   * {@code StandaloneThreadPropagationContext.wrap(...)}, submitted
   * tasks run with the submitter's subject bound on the worker
   * thread and the binding is cleared on return.
   *
   * @return this builder
   */
  public ThreadPropagationBuilder inheritOnSubmit() {
    this.mode = ThreadPropagationMode.INHERIT_ON_SUBMIT;
    return this;
  }

  /**
   * Explicitly selects {@link ThreadPropagationMode#NONE} (the
   * default). Useful as a self-documenting marker.
   *
   * @return this builder
   */
  public ThreadPropagationBuilder none() {
    this.mode = ThreadPropagationMode.NONE;
    return this;
  }

  /**
   * Sets the propagation mode directly.
   *
   * @param mode non-null mode
   * @return this builder
   */
  public ThreadPropagationBuilder mode(ThreadPropagationMode mode) {
    this.mode = Objects.requireNonNull(mode, "mode");
    return this;
  }

  ThreadPropagationStrategy toStrategy() {
    return new ThreadPropagationStrategy(mode);
  }
}
