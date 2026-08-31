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
package eu.jsentinel.jcustos.dx.vaadin.bootstrap;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.vaadin.VaadinSessionSubjectStore;
import eu.jsentinel.jcustos.dx.bootstrap.JSentinelBootstrapException;
import eu.jsentinel.jcustos.dx.internal.AbstractJSentinelBootstrap;
import eu.jsentinel.jcustos.dx.runtime.RegisteredJSentinelService;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapMode;
import eu.jsentinel.jcustos.dx.runtime.JSentinelBootstrapWarning;
import eu.jsentinel.jcustos.dx.runtime.JSentinelRuntime;
import eu.jsentinel.jcustos.dx.runtime.Severity;
import eu.jsentinel.jcustos.dx.vaadin.routes.SecureRouteDiscovery;
import eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementContext;
import eu.jsentinel.jcustos.dx.vaadin.routes.SessionManagementRoute;
import eu.jsentinel.jcustos.dx.vaadin.routes.VaadinRouteContext;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Package-private implementation of {@link VaadinJSentinelBootstrap}.
 * <p>
 * Single-use: a second {@code install()} call throws.
 *
 * @since 00.72.00
 */
final class VaadinJSentinelBootstrapImpl
    extends AbstractJSentinelBootstrap<VaadinJSentinelBootstrap>
    implements VaadinJSentinelBootstrap {

  private Class<?> subjectType;
  private String loginRoute;
  private String stepUpRoute;
  private boolean securedComponents;
  private boolean sessionManagementView;
  private boolean installed;

  private boolean discoverSecureRoutesEnabled;
  private SecureRouteDiscovery secureRouteDiscovery;

  private Class<?> errorView;
  private String afterLoginRoute;
  private String passwordResetRoute;

  @Override
  public VaadinJSentinelBootstrap subjectType(Class<?> subjectType) {
    this.subjectType = Objects.requireNonNull(subjectType, "subjectType");
    return this;
  }

  @Override
  public VaadinJSentinelBootstrap loginRoute(String route) {
    this.loginRoute = Objects.requireNonNull(route, "route");
    return this;
  }

  @Override
  public VaadinJSentinelBootstrap stepUpRoute(String route) {
    this.stepUpRoute = Objects.requireNonNull(route, "route");
    return this;
  }

  @Override
  public VaadinJSentinelBootstrap securedComponents() {
    this.securedComponents = true;
    return this;
  }

  @Override
  public VaadinJSentinelBootstrap sessionManagementView() {
    this.sessionManagementView = true;
    return this;
  }

  @Override
  public VaadinJSentinelBootstrap errorView(Class<?> errorViewClass) {
    this.errorView = Objects.requireNonNull(errorViewClass, "errorViewClass");
    return this;
  }

  @Override
  public VaadinJSentinelBootstrap afterLoginRoute(String route) {
    this.afterLoginRoute = requireNonBlankRoute(route, "afterLoginRoute");
    return this;
  }

  @Override
  public VaadinJSentinelBootstrap passwordResetRoute(String route) {
    this.passwordResetRoute = requireNonBlankRoute(route, "passwordResetRoute");
    return this;
  }

  private static String requireNonBlankRoute(String route, String name) {
    Objects.requireNonNull(route, name);
    if (route.isBlank()) {
      throw new IllegalArgumentException(name + " must not be blank");
    }
    return route;
  }

  @Override
  public VaadinJSentinelBootstrap discoverSecureRoutes(boolean enabled) {
    this.discoverSecureRoutesEnabled = enabled;
    return this;
  }

  @Override
  public VaadinJSentinelBootstrap discoverSecureRoutes(SecureRouteDiscovery discovery) {
    this.secureRouteDiscovery = Objects.requireNonNull(discovery, "discovery");
    this.discoverSecureRoutesEnabled = true;
    return this;
  }

  @Override
  public JSentinelRuntime install() {
    if (installed) {
      throw new IllegalStateException("install() may only be called once on the same builder");
    }
    installed = true;

    List<RegisteredJSentinelService> services = new ArrayList<>();
    List<JSentinelBootstrapWarning> warnings = new ArrayList<>();

    AuthenticationService<?, ?> authn = state.authenticationService();
    AuthorizationService<?> authz = state.authorizationService();

    if (authn != null) {
      JSentinelServiceResolver.setAuthenticationService(authn);
      services.add(new RegisteredJSentinelService(
          AuthenticationService.class, authn.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new JSentinelBootstrapWarning(
          Severity.ERROR,
          "missing-authentication-service",
          "No AuthenticationService configured for VaadinSecurity.bootstrap().",
          "Call .authentication(...) before install(), or register an implementation "
              + "via @JSentinelAutoService(AuthenticationService.class)."));
    }

    if (authz != null) {
      JSentinelServiceResolver.setAuthorizationService(authz);
      services.add(new RegisteredJSentinelService(
          AuthorizationService.class, authz.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new JSentinelBootstrapWarning(
          Severity.ERROR,
          "missing-authorization-service",
          "No AuthorizationService configured for VaadinSecurity.bootstrap().",
          "Call .authorization(...) before install(), or register an implementation "
              + "via @JSentinelAutoService(AuthorizationService.class)."));
    }

    if (stepUpRoute != null) {
      JSentinelServiceResolver.setStepUpRouteName(stepUpRoute);
    }

    // R05-Rest (V00.76.10): the shared per-concern sub-builder consumption
    // (direct-set services, audit, sessions, roles, credentials, policies,
    // propagation, JWT) — identical across adapters — is hoisted into the base.
    applyCommonConfiguration(AdapterKind.VAADIN, services, warnings);

    // V00.73 (Prompt 012 / Konzept §8.5): deterministic SecureRoute
    // cross-validation if discovery is opt-in.
    crossCheckSecureRoutes(warnings);

    // V00.73 (Prompt 009): auto-wire VaadinSessionSubjectStore as the
    // default SubjectStore when the consumer didn't register one.
    // Caller-provided SubjectStore (via SubjectStores.setSubjectStore
    // or @JSentinelAutoService(SubjectStore.class)) always wins.
    if (SubjectStores.findSubjectStore().isEmpty()) {
      SubjectStore defaultStore = new VaadinSessionSubjectStore();
      SubjectStores.setSubjectStore(defaultStore);
      services.add(new RegisteredJSentinelService(
          SubjectStore.class, defaultStore.getClass(), "bootstrap-default", true));
    } else {
      SubjectStore existing = SubjectStores.subjectStore();
      services.add(new RegisteredJSentinelService(
          SubjectStore.class, existing.getClass(), "bootstrap-explicit", false));
    }

    // V00.73 (Prompt 008): SessionManagementView activation.
    // Validates the prerequisite (SessionStore present) and
    // publishes the store into SessionManagementContext so the
    // SessionManagementRoute can instantiate when Vaadin auto-
    // discovers it on the classpath.
    if (sessionManagementView) {
      var sessionStore = state.sessionState().sessionStore();
      if (sessionStore == null) {
        warnings.add(new JSentinelBootstrapWarning(
            Severity.ERROR,
            "session-management-view-without-session-store",
            ".sessionManagementView() was set but no SessionStore is configured.",
            "Call .sessions(s -> s.storeBacked(yourSessionStore)) before .sessionManagementView()."));
      } else {
        SessionManagementContext.publish(sessionStore, null);
        services.add(new RegisteredJSentinelService(
            SessionManagementRoute.class, SessionManagementRoute.class,
            "bootstrap-activated", false));
      }
    }

    // V00.74 (A2.1): publish Vaadin route hints for the starter to
    // pick up at attach time. errorView is mandatory-class, the two
    // route names are mandatory-non-blank (validated on the setter).
    if (errorView != null) {
      VaadinRouteContext.publishErrorView(errorView);
      services.add(new RegisteredJSentinelService(
          VaadinRouteContext.class, errorView, "bootstrap-error-view", false));
    }
    if (afterLoginRoute != null) {
      VaadinRouteContext.publishAfterLoginRoute(afterLoginRoute);
      services.add(new RegisteredJSentinelService(
          VaadinRouteContext.class, String.class,
          "bootstrap-after-login=" + afterLoginRoute, false));
    }
    if (passwordResetRoute != null) {
      VaadinRouteContext.publishPasswordResetRoute(passwordResetRoute);
      services.add(new RegisteredJSentinelService(
          VaadinRouteContext.class, String.class,
          "bootstrap-password-reset=" + passwordResetRoute, false));
    }

    JSentinelBootstrapMode mode = state.mode();

    if (mode == JSentinelBootstrapMode.STRICT && warningsContainError(warnings)) {
      throw new JSentinelBootstrapException(warnings);
    }

    // Suppress unused-warning until the starter consumes these in Phase 3.
    discard(subjectType);
    discard(loginRoute);
    discard(securedComponents);

    return new JSentinelRuntime(services, warnings, mode);
  }

  @SuppressWarnings("unused")
  private static void discard(Object ignored) {
    // intentional no-op
  }

  /**
   * Konzept §8.5 deterministic SecureRoute cross-validation.
   * Only runs when {@code .discoverSecureRoutes(true)} or a custom
   * {@link SecureRouteDiscovery} was configured. Without opt-in,
   * emits {@code secure-route/discovery-disabled} (INFO).
   */
  private void crossCheckSecureRoutes(List<JSentinelBootstrapWarning> warnings) {
    // JS-SEC-024 (CWE-862): the deny-by-default startup safety-net must fire whenever
    // deny-by-default is enabled — independent of the @SecureRoute discovery opt-in.
    // Otherwise STRICT boots green while un-annotated routes would only be denied at first
    // navigation, contradicting setDenyByDefault's "surface at boot" contract. Uses the
    // explicit discovery if set, else the default impl (no-op when none is on the classpath).
    if (JSentinelServiceResolver.isDenyByDefault()) {
      SecureRouteDiscovery denyDiscovery = secureRouteDiscovery != null
          ? secureRouteDiscovery
          : tryLoadDefaultDiscovery();
      if (denyDiscovery != null && !denyDiscovery.routesAvailable()) {
        // RF (exit-review, RF03): discovery could not read the route registry (e.g. no
        // active VaadinService at bootstrap). An empty result must NOT be trusted as
        // "no un-annotated routes" — that would let STRICT boot green while every
        // un-annotated route is denied only at first navigation. Surface it loudly.
        warnings.add(new JSentinelBootstrapWarning(
            Severity.ERROR,
            "deny-by-default/discovery-unavailable",
            "deny-by-default is enabled but the Vaadin route registry could not be read at "
                + "bootstrap, so un-annotated routes cannot be surfaced now.",
            "Run VaadinSecurity.bootstrap().install() where a VaadinService is active (e.g. from "
                + "a VaadinServiceInitListener), or pass an explicit SecureRouteDiscovery."));
      } else if (denyDiscovery != null) {
        denyDiscovery.discoverUnannotatedRouteNames().forEach(routeName ->
            warnings.add(new JSentinelBootstrapWarning(
                Severity.ERROR,
                "deny-by-default/unannotated-route",
                "Route " + routeName + " has no security annotation and is not @PublicRoute; "
                    + "deny-by-default will deny all navigation to it.",
                "Add a restriction annotation (@RequiresRole / @RequiresPermission / "
                    + "@SecureRoute), or mark it @PublicRoute if it is intentionally public.")));
      }
    }

    if (!discoverSecureRoutesEnabled) {
      warnings.add(new JSentinelBootstrapWarning(
          Severity.INFO,
          "secure-route/discovery-disabled",
          "@SecureRoute(policy=...) cross-validation is opt-in; deterministic STRICT checks are disabled.",
          "Call .discoverSecureRoutes(true) to enable Vaadin-router-based discovery."));
      return;
    }
    SecureRouteDiscovery discovery = secureRouteDiscovery != null
        ? secureRouteDiscovery
        : tryLoadDefaultDiscovery();
    if (discovery == null) {
      // discovery requested but no impl available — STRICT still
      // benefits, but at least surface the diagnostic
      warnings.add(new JSentinelBootstrapWarning(
          Severity.ERROR,
          "secure-route/discovery-unavailable",
          ".discoverSecureRoutes(true) was set, but no SecureRouteDiscovery implementation is on the classpath.",
          "Add security-vaadin-starter, or pass an explicit SecureRouteDiscovery via .discoverSecureRoutes(impl)."));
      return;
    }
    java.util.Set<String> knownNames = state.policyState().knownPolicyNames();
    discovery.discoverPolicyNames().forEach(policyName -> {
      if (!knownNames.contains(policyName)) {
        warnings.add(new JSentinelBootstrapWarning(
            Severity.ERROR,
            "secure-route/unknown-policy",
            "@SecureRoute(policy=\"" + policyName
                + "\") references an unknown policy.",
            "Register the policy via .policies(p -> p.register(Policy.named(\""
                + policyName + "\")...)), or fix the @SecureRoute annotation."));
      }
    });
    // R035: a constraint-less @SecureRoute is fail-closed to "any authenticated
    // subject" (safe), but a missing constraint is often an oversight — surface
    // it as a non-fatal advisory (WARNING, not STRICT-ERROR, so a deliberate
    // authenticated-only route is not blocked).
    discovery.discoverConstraintlessRouteNames().forEach(routeName ->
        warnings.add(new JSentinelBootstrapWarning(
            Severity.WARNING,
            "secure-route/no-constraints",
            "@SecureRoute on " + routeName + " declares no roles, permissions or "
                + "policy; it grants any authenticated subject.",
            "Add roles/permissions/policy to restrict further, or keep it if an "
                + "authenticated-only route is intended.")));
  }

  private static SecureRouteDiscovery tryLoadDefaultDiscovery() {
    try {
      Class<?> defaultImpl = Class.forName(
          "eu.jsentinel.jcustos.starter.routes.VaadinRouterSecureRouteDiscovery");
      return (SecureRouteDiscovery) defaultImpl.getDeclaredConstructor().newInstance();
    } catch (ReflectiveOperationException ignored) {
      return null;
    }
  }
}
