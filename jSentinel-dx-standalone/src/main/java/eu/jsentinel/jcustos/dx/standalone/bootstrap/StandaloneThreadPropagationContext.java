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

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;

import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Static publication point + helper for the V00.74 thread-propagation
 * strategy collected by {@code StandaloneJCustosBootstrap}.
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
   * <p>R06 (V00.76.10): this holder is <strong>process-global</strong> (one per
   * JVM). Re-publishing an equal strategy is idempotent; publishing a different
   * one while one is already active throws rather than silently overwriting (the
   * multi-app-in-one-JVM hazard). Run one bootstrap per JVM or call
   * {@link #reset()} between intentional re-inits.
   *
   * @param strategy strategy; non-null
   * @throws IllegalStateException if a different strategy is already published
   */
  public static void publish(ThreadPropagationStrategy strategy) {
    Objects.requireNonNull(strategy, "strategy");
    ThreadPropagationStrategy existing = STRATEGY.get();
    if (existing != null && !existing.equals(strategy)) {
      throw new IllegalStateException(
          "StandaloneThreadPropagationContext already holds a different strategy. "
              + "This holder is process-global (one per JVM); use one bootstrap per "
              + "JVM, or call reset() between intentional re-inits.");
    }
    STRATEGY.set(strategy);
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
      // R13 (V00.76.10): the subject is bound in the store under the application's
      // subject type (AuthenticationService.subjectType(), e.g. User.class) — see
      // StandaloneLoginFlow#login — NOT under JCustosSubject.class. Capturing
      // and rebinding under JCustosSubject.class therefore always missed, so the
      // propagated worker ran with no subject: fail-closed, but the advertised
      // .threadPropagation(t -> t.inheritOnSubmit()) feature was silently dead.
      // Resolve the same type key the login flow uses.
      Class<?> subjectType = JCustosServiceResolver.findAuthenticationService()
          .map(AuthenticationService::subjectType)
          .orElse(null);
      Object captured = subjectType == null
          ? null
          : SubjectStores.findSubjectStore()
              .flatMap(s -> s.currentSubject(subjectType))
              .orElse(null);
      delegate.execute(() -> {
        if (captured == null) {
          command.run();
          return;
        }
        SubjectStore store = SubjectStores.subjectStore();
        Object prior = store.currentSubject(subjectType).orElse(null);
        bind(store, captured, subjectType);
        try {
          command.run();
        } finally {
          if (prior != null) {
            bind(store, prior, subjectType);
          } else {
            store.deleteCurrentSubject(subjectType);
          }
        }
      });
    }

    /** Bridges the {@code Class<?>} key to the store's {@code <T>} setter. */
    private static <T> void bind(SubjectStore store, Object subject, Class<T> type) {
      store.setCurrentSubject(type.cast(subject), type);
    }
  }
}
