/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.dx.standalone.bootstrap;

import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.bruteforce.LoginAttemptPolicy;
import eu.jsentinel.jcustos.dx.bootstrap.CommonJCustosBootstrap;

import java.util.function.Consumer;

/**
 * Standalone-specific fluent bootstrap. Entry point:
 * {@link StandaloneSecurity#bootstrap()}.
 *
 * @since 00.72.00
 */
public interface StandaloneJCustosBootstrap
    extends CommonJCustosBootstrap<StandaloneJCustosBootstrap> {

  StandaloneJCustosBootstrap subjectStore(SubjectStore store);

  /**
   * @deprecated since 00.74.00 — use
   *             {@link CommonJCustosBootstrap#bruteForce(LoginAttemptPolicy)}
   *             instead. The two methods are wired identically; the
   *             standalone-specific method is kept for source-backwards
   *             compatibility.
   */
  @Deprecated(since = "00.74.00")
  StandaloneJCustosBootstrap loginAttemptPolicy(LoginAttemptPolicy policy);

  /**
   * V00.74: Configures the thread-propagation strategy. The
   * published {@link ThreadPropagationStrategy} is consumed by
   * {@link StandaloneThreadPropagationContext#wrap(java.util.concurrent.Executor)}
   * so submitted tasks inherit the submitter's subject on the
   * worker thread (when {@code INHERIT_ON_SUBMIT} is selected).
   *
   * @param consumer non-null consumer that configures the
   *                 {@link ThreadPropagationBuilder}
   * @return this builder
   * @since 00.74.00
   */
  StandaloneJCustosBootstrap threadPropagation(Consumer<ThreadPropagationBuilder> consumer);

  /**
   * V00.74: Configures the interactive (CLI / desktop) login
   * pattern. The published {@link InteractiveLoginConfiguration}
   * is consumed by the application's login loop — the library
   * does not run the loop itself.
   *
   * @param consumer non-null consumer that configures the
   *                 {@link InteractiveLoginBuilder}
   * @return this builder
   * @since 00.74.00
   */
  StandaloneJCustosBootstrap interactiveLogin(Consumer<InteractiveLoginBuilder> consumer);
}
