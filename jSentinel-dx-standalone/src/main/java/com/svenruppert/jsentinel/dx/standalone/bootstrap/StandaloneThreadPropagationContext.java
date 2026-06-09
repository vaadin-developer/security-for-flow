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
package com.svenruppert.jsentinel.dx.standalone.bootstrap;

import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.api.SubjectStores;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Static publication point + helper for the V00.74 thread-propagation
 * strategy collected by {@code StandaloneJSentinelBootstrap}.
 *
 * <p>{@link #wrap(Executor)} returns an {@code Executor} that
 * captures the submitter's subject at {@code execute(Runnable)} time
 * and binds it on the worker thread for the duration of the task,
 * then restores the worker's previous binding. Without an explicit
 * {@code .threadPropagation(t -> t.inheritOnSubmit())}, the wrapper
 * is a pass-through (matches the V00.70 default: per-thread,
 * not-inherited).
 *
 * @since 00.74.00
 */
public final class StandaloneThreadPropagationContext {

  private static final AtomicReference<ThreadPropagationStrategy> STRATEGY = new AtomicReference<>();

  private StandaloneThreadPropagationContext() {
    throw new AssertionError("no instances");
  }

  /**
   * Publishes the active propagation strategy.
   *
   * @param strategy strategy; non-null
   */
  public static void publish(ThreadPropagationStrategy strategy) {
    STRATEGY.set(Objects.requireNonNull(strategy, "strategy"));
  }

  /** @return the active strategy, if configured */
  public static Optional<ThreadPropagationStrategy> strategy() {
    return Optional.ofNullable(STRATEGY.get());
  }

  /** Test helper: clears the holder. */
  public static void reset() {
    STRATEGY.set(null);
  }

  /**
   * Wraps {@code delegate} so submitted tasks inherit the
   * submitter's subject when the configured strategy is
   * {@link ThreadPropagationMode#INHERIT_ON_SUBMIT}; otherwise the
   * wrapper is a pass-through.
   *
   * @param delegate underlying executor; non-null
   * @return wrapped executor
   */
  public static Executor wrap(Executor delegate) {
    Objects.requireNonNull(delegate, "delegate");
    ThreadPropagationStrategy current = STRATEGY.get();
    if (current == null || current.mode() != ThreadPropagationMode.INHERIT_ON_SUBMIT) {
      return delegate;
    }
    return new InheritingExecutor(delegate);
  }

  private record InheritingExecutor(Executor delegate) implements Executor {

    @Override
    public void execute(Runnable command) {
      Objects.requireNonNull(command, "command");
      JSentinelSubject captured = SubjectStores.findSubjectStore()
          .flatMap(s -> s.currentSubject(JSentinelSubject.class))
          .orElse(null);
      delegate.execute(() -> {
        if (captured == null) {
          command.run();
          return;
        }
        var store = SubjectStores.subjectStore();
        JSentinelSubject prior = store.currentSubject(JSentinelSubject.class).orElse(null);
        store.setCurrentSubject(captured, JSentinelSubject.class);
        try {
          command.run();
        } finally {
          if (prior != null) {
            store.setCurrentSubject(prior, JSentinelSubject.class);
          } else {
            store.deleteCurrentSubject(JSentinelSubject.class);
          }
        }
      });
    }
  }
}
