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
package com.svenruppert.vaadin.security.starter.ui;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.components.SecuredVisibilityMode;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.policy.api.Policy;
import com.svenruppert.vaadin.security.policy.api.PolicyContext;
import com.svenruppert.vaadin.security.policy.api.PolicyDecision;
import com.svenruppert.vaadin.security.policy.spi.PolicyRegistry;
import com.vaadin.flow.component.Component;

import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * V00.73 policy-aware visibility helper for {@link SecuredUi}.
 *
 * <p>Adds an attach listener that resolves the current
 * {@link SecuritySubject}, builds a {@link PolicyContext}, and asks
 * the configured {@link PolicyRegistry} how to render the component.
 * The same instance is re-evaluated on every attach so navigation
 * between routes refreshes the decision (mirrors V00.71
 * {@code SecuredVisibility.apply(...)} semantics).
 *
 * <p>Diagnostic logging differentiates the two denial paths
 * (Konzept §8.4):
 * <ul>
 *   <li>"no subject" — log INFO {@code secured-ui/no-subject}</li>
 *   <li>"policy denied" — log FINE {@code secured-ui/policy-denied}</li>
 *   <li>"unknown policy" — log WARNING {@code secured-ui/unknown-policy}</li>
 * </ul>
 *
 * @since 00.73.00
 */
final class PolicyVisibility {

  private static final Logger LOG = Logger.getLogger(PolicyVisibility.class.getName());

  private PolicyVisibility() {
    throw new AssertionError("no instances");
  }

  /**
   * Wires {@code component} to evaluate {@code policyName} on attach.
   * Applies the chosen visibility {@code mode} on denied/missing.
   */
  static void install(Component component, String policyName, SecuredVisibilityMode mode) {
    component.addAttachListener(e -> applyOnce(component, policyName, mode));
    // Also evaluate immediately so tests that don't go through Vaadin's
    // attach lifecycle still see the initial verdict.
    applyOnce(component, policyName, mode);
  }

  private static void applyOnce(Component component, String policyName, SecuredVisibilityMode mode) {
    Verdict v = evaluate(policyName);
    switch (v) {
      case Allowed -> show(component);
      case DeniedNoSubject -> {
        LOG.log(Level.INFO,
            () -> "secured-ui/no-subject: policy=" + policyName + " — no subject bound");
        denyVisible(component, mode);
      }
      case DeniedByPolicy -> {
        LOG.log(Level.FINE,
            () -> "secured-ui/policy-denied: policy=" + policyName);
        denyVisible(component, mode);
      }
      case UnknownPolicy -> {
        LOG.log(Level.WARNING,
            () -> "secured-ui/unknown-policy: policy=" + policyName + " — PolicyRegistry has no entry");
        denyVisible(component, mode);
      }
      case StepUpRequired -> {
        LOG.log(Level.FINE,
            () -> "secured-ui/step-up-required: policy=" + policyName);
        // Treat step-up like a denial at the UI layer; the route-level
        // @SecureRoute(policy=...) handles step-up navigation.
        denyVisible(component, mode);
      }
      default -> denyVisible(component, mode);
    }
  }

  private static Verdict evaluate(String policyName) {
    SecuritySubject subject = resolveSubject().orElse(null);
    if (subject == null) {
      return Verdict.DeniedNoSubject;
    }
    PolicyRegistry registry = SecurityServiceResolver.policyRegistry();
    Optional<Policy> known = registry.find(policyName);
    if (known.isEmpty()) {
      return Verdict.UnknownPolicy;
    }
    AccessContext ac = new AccessContext(
        Optional.of(subject),
        "ui-component",
        policyName,
        "evaluate",
        java.util.Map.of());
    PolicyContext pc = new PolicyContext(ac, policyName);
    PolicyDecision decision = registry.evaluate(policyName, pc);
    if (decision instanceof PolicyDecision.Allowed) {
      return Verdict.Allowed;
    }
    if (decision instanceof PolicyDecision.StepUpRequired) {
      return Verdict.StepUpRequired;
    }
    return Verdict.DeniedByPolicy;
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private static Optional<SecuritySubject> resolveSubject() {
    try {
      Class subjectType = SecurityServiceResolver
          .<Object, Object>findAuthenticationService()
          .map(AuthenticationService::subjectType)
          .orElse(null);
      if (subjectType == null) {
        return Optional.empty();
      }
      Optional<Object> rawSubject = SubjectStores.findSubjectStore()
          .flatMap(store -> store.currentSubject(subjectType));
      if (rawSubject.isEmpty()) {
        return Optional.empty();
      }
      Optional<AuthorizationService<Object>> authzOpt =
          SecurityServiceResolver.findAuthorizationService();
      if (authzOpt.isEmpty()) {
        return Optional.empty();
      }
      AuthorizationService<Object> authz = authzOpt.get();
      Object u = rawSubject.get();
      return Optional.of(new SecuritySubject(
          String.valueOf(u),
          String.valueOf(u),
          new java.util.LinkedHashSet<>(authz.rolesFor(u).roleNames()),
          new java.util.LinkedHashSet<>(authz.permissionsFor(u).permissionNames())));
    } catch (RuntimeException ignored) {
      return Optional.empty();
    }
  }

  private static void show(Component c) {
    c.setVisible(true);
    if (c instanceof com.vaadin.flow.component.HasEnabled he) {
      he.setEnabled(true);
    }
  }

  private static void denyVisible(Component c, SecuredVisibilityMode mode) {
    if (mode == SecuredVisibilityMode.HIDE) {
      c.setVisible(false);
      return;
    }
    if (c instanceof com.vaadin.flow.component.HasEnabled he) {
      he.setEnabled(false);
    } else {
      c.setVisible(false);
    }
  }

  private enum Verdict {
    Allowed, DeniedNoSubject, DeniedByPolicy, UnknownPolicy, StepUpRequired
  }
}
