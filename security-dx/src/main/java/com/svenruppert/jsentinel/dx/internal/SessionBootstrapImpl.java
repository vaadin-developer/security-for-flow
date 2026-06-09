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
package com.svenruppert.jsentinel.dx.internal;

import com.svenruppert.jsentinel.authorization.api.SubjectIdResolver;
import com.svenruppert.jsentinel.dx.bootstrap.SessionBootstrap;
import com.svenruppert.jsentinel.session.JSentinelVersionStore;
import com.svenruppert.jsentinel.session.SessionPolicy;
import com.svenruppert.jsentinel.session.SessionStore;

import java.time.Duration;
import java.util.Objects;

/**
 * Real V00.73 implementation of {@link SessionBootstrap}. Records
 * every selection into the {@link SessionState} held by
 * {@link BootstrapState}; {@code install()} consumes the state and
 * wires the appropriate {@code JSentinelServiceResolver} setters.
 *
 * <p>{@link #storeBacked(SessionStore)} accepts {@code null} so the
 * install-time validator can emit the stable
 * {@code sessions/missing-store} code for both "null store" and
 * "timeout without store" cases.
 *
 * @since 00.73.00
 */
final class SessionBootstrapImpl implements SessionBootstrap {

  private final SessionState state;

  SessionBootstrapImpl(SessionState state) {
    this.state = Objects.requireNonNull(state, "state");
  }

  @Override
  public SessionBootstrap storeBacked(SessionStore store) {
    state.sessionStore(store);
    return this;
  }

  @Override
  public SessionBootstrap securityVersion(JSentinelVersionStore store) {
    state.securityVersionStore(Objects.requireNonNull(store, "store"));
    return this;
  }

  @Override
  public SessionBootstrap subjectIdResolver(SubjectIdResolver<?> resolver) {
    state.subjectIdResolver(Objects.requireNonNull(resolver, "resolver"));
    return this;
  }

  @Override
  public SessionBootstrap timeout(Duration idleTimeout) {
    state.idleTimeout(idleTimeout);
    return this;
  }

  @Override
  public SessionBootstrap absoluteLifetime(Duration absoluteTimeout) {
    state.absoluteLifetime(absoluteTimeout);
    return this;
  }

  @Override
  public SessionBootstrap policy(SessionPolicy<?> policy) {
    state.policy(Objects.requireNonNull(policy, "policy"));
    return this;
  }
}
