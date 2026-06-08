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

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;

/**
 * Mutable aggregate of accumulated configuration during a fluent
 * bootstrap call. Reset to a fresh instance per bootstrap call.
 * <p>
 * <strong>Internal API.</strong> Used by {@link AbstractSecurityBootstrap}
 * and adapter-DX module subclasses; not part of the V00.72 public surface.
 *
 * @since 00.72.00
 */
public final class BootstrapState {

  private AuthenticationService<?, ?> authenticationService;
  private AuthorizationService<?> authorizationService;
  private SecurityBootstrapMode mode = SecurityBootstrapMode.COMMUNITY_DEFAULTS;

  private boolean auditConfigured;
  private boolean sessionsConfigured;
  private boolean policiesConfigured;
  private boolean rolesConfigured;
  private boolean credentialsConfigured;

  private final AuditState auditState = new AuditState();

  /** @return the typed audit sub-aggregate (V00.73) */
  public AuditState auditState() {
    return auditState;
  }

  public AuthenticationService<?, ?> authenticationService() {
    return authenticationService;
  }

  public void authenticationService(AuthenticationService<?, ?> service) {
    this.authenticationService = service;
  }

  public AuthorizationService<?> authorizationService() {
    return authorizationService;
  }

  public void authorizationService(AuthorizationService<?> service) {
    this.authorizationService = service;
  }

  public SecurityBootstrapMode mode() {
    return mode;
  }

  public void mode(SecurityBootstrapMode mode) {
    if (mode != null) {
      this.mode = mode;
    }
  }

  public boolean auditConfigured() {
    return auditConfigured;
  }

  public void markAuditConfigured() {
    this.auditConfigured = true;
  }

  public boolean sessionsConfigured() {
    return sessionsConfigured;
  }

  public void markSessionsConfigured() {
    this.sessionsConfigured = true;
  }

  public boolean policiesConfigured() {
    return policiesConfigured;
  }

  public void markPoliciesConfigured() {
    this.policiesConfigured = true;
  }

  public boolean rolesConfigured() {
    return rolesConfigured;
  }

  public void markRolesConfigured() {
    this.rolesConfigured = true;
  }

  public boolean credentialsConfigured() {
    return credentialsConfigured;
  }

  public void markCredentialsConfigured() {
    this.credentialsConfigured = true;
  }
}
