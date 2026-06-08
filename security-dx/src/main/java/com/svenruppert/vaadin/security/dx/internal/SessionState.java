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
package com.svenruppert.vaadin.security.dx.internal;

import com.svenruppert.vaadin.security.authorization.api.SubjectIdResolver;
import com.svenruppert.vaadin.security.session.SecurityVersionStore;
import com.svenruppert.vaadin.security.session.SessionPolicy;
import com.svenruppert.vaadin.security.session.SessionStore;

import java.time.Duration;

/**
 * Sub-aggregate of {@link BootstrapState} holding everything the
 * {@code .sessions(...)} sub-builder records during a fluent
 * bootstrap call.
 *
 * <p><strong>Internal API.</strong> Not part of the V00.72 public
 * surface.
 *
 * @since 00.73.00
 */
public final class SessionState {

  private SessionStore sessionStore;
  private SecurityVersionStore securityVersionStore;
  private SubjectIdResolver<?> subjectIdResolver;
  private Duration idleTimeout;
  private Duration absoluteLifetime;
  private SessionPolicy<?> policy;
  private boolean timeoutConfigured;
  private boolean absoluteLifetimeConfigured;

  public SessionStore sessionStore() {
    return sessionStore;
  }

  public void sessionStore(SessionStore store) {
    this.sessionStore = store;
  }

  public SecurityVersionStore securityVersionStore() {
    return securityVersionStore;
  }

  public void securityVersionStore(SecurityVersionStore store) {
    this.securityVersionStore = store;
  }

  public SubjectIdResolver<?> subjectIdResolver() {
    return subjectIdResolver;
  }

  public void subjectIdResolver(SubjectIdResolver<?> resolver) {
    this.subjectIdResolver = resolver;
  }

  public Duration idleTimeout() {
    return idleTimeout;
  }

  public boolean timeoutConfigured() {
    return timeoutConfigured;
  }

  public void idleTimeout(Duration timeout) {
    this.idleTimeout = timeout;
    this.timeoutConfigured = true;
  }

  public Duration absoluteLifetime() {
    return absoluteLifetime;
  }

  public boolean absoluteLifetimeConfigured() {
    return absoluteLifetimeConfigured;
  }

  public void absoluteLifetime(Duration lifetime) {
    this.absoluteLifetime = lifetime;
    this.absoluteLifetimeConfigured = true;
  }

  public SessionPolicy<?> policy() {
    return policy;
  }

  public void policy(SessionPolicy<?> policy) {
    this.policy = policy;
  }

  /**
   * @return {@code true} when any selection method ran at all —
   *         {@code .sessions(s -> {})} returns {@code false} here
   */
  public boolean hasAnySelection() {
    return sessionStore != null
        || securityVersionStore != null
        || subjectIdResolver != null
        || timeoutConfigured
        || absoluteLifetimeConfigured
        || policy != null;
  }
}
