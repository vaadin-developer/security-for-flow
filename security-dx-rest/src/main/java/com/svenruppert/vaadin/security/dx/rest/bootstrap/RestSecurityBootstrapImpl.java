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
package com.svenruppert.vaadin.security.dx.rest.bootstrap;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.dx.bootstrap.SecurityBootstrapException;
import com.svenruppert.vaadin.security.dx.internal.AbstractSecurityBootstrap;
import com.svenruppert.vaadin.security.dx.runtime.RegisteredSecurityService;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapMode;
import com.svenruppert.vaadin.security.dx.runtime.SecurityBootstrapWarning;
import com.svenruppert.vaadin.security.dx.runtime.SecurityRuntime;
import com.svenruppert.vaadin.security.dx.runtime.Severity;
import com.svenruppert.vaadin.security.rest.RestSubjectResolver;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Package-private implementation of {@link RestSecurityBootstrap}.
 *
 * @since 00.72.00
 */
final class RestSecurityBootstrapImpl
    extends AbstractSecurityBootstrap<RestSecurityBootstrap>
    implements RestSecurityBootstrap {

  private RestSubjectResolver subjectResolver;
  private RestDecisionMapper decisionMapper;
  private RestErrorBodyStrategy errorBodies;
  private boolean installed;

  @Override
  public RestSecurityBootstrap subjectResolver(RestSubjectResolver resolver) {
    this.subjectResolver = Objects.requireNonNull(resolver, "resolver");
    return this;
  }

  @Override
  public RestSecurityBootstrap decisionMapper(RestDecisionMapper mapper) {
    this.decisionMapper = Objects.requireNonNull(mapper, "mapper");
    return this;
  }

  @Override
  public RestSecurityBootstrap errorBodies(RestErrorBodyStrategy strategy) {
    this.errorBodies = Objects.requireNonNull(strategy, "strategy");
    return this;
  }

  @Override
  public SecurityRuntime install() {
    if (installed) {
      throw new IllegalStateException("install() may only be called once on the same builder");
    }
    installed = true;

    List<RegisteredSecurityService> services = new ArrayList<>();
    List<SecurityBootstrapWarning> warnings = new ArrayList<>();

    AuthenticationService<?, ?> authn = state.authenticationService();
    AuthorizationService<?> authz = state.authorizationService();

    if (authn != null) {
      SecurityServiceResolver.setAuthenticationService(authn);
      services.add(new RegisteredSecurityService(
          AuthenticationService.class, authn.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "missing-authentication-service",
          "No AuthenticationService configured for RestSecurity.bootstrap().",
          "Call .authentication(...) or register an implementation via "
              + "@SecurityAutoService(AuthenticationService.class)."));
    }

    if (authz != null) {
      SecurityServiceResolver.setAuthorizationService(authz);
      services.add(new RegisteredSecurityService(
          AuthorizationService.class, authz.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "missing-authorization-service",
          "No AuthorizationService configured for RestSecurity.bootstrap().",
          "Call .authorization(...) or register an implementation via "
              + "@SecurityAutoService(AuthorizationService.class)."));
    }

    if (subjectResolver != null) {
      services.add(new RegisteredSecurityService(
          RestSubjectResolver.class, subjectResolver.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new SecurityBootstrapWarning(
          Severity.ERROR,
          "missing-rest-subject-resolver",
          "No RestSubjectResolver configured for RestSecurity.bootstrap().",
          "Call .subjectResolver(...) or register an implementation via "
              + "@SecurityAutoService(RestSubjectResolver.class)."));
    }

    RestDecisionMapper effectiveDecisionMapper = decisionMapper;
    boolean decisionMapperDefaulted = false;
    if (effectiveDecisionMapper == null) {
      effectiveDecisionMapper = new DefaultRestDecisionMapper();
      decisionMapperDefaulted = true;
    }
    services.add(new RegisteredSecurityService(
        RestDecisionMapper.class,
        effectiveDecisionMapper.getClass(),
        decisionMapperDefaulted ? "bootstrap-default" : "bootstrap-explicit",
        decisionMapperDefaulted));

    RestErrorBodyStrategy effectiveErrorBodies = errorBodies;
    boolean errorBodiesDefaulted = false;
    if (effectiveErrorBodies == null) {
      effectiveErrorBodies = new DefaultRestErrorBodyStrategy();
      errorBodiesDefaulted = true;
    }
    services.add(new RegisteredSecurityService(
        RestErrorBodyStrategy.class,
        effectiveErrorBodies.getClass(),
        errorBodiesDefaulted ? "bootstrap-default" : "bootstrap-explicit",
        errorBodiesDefaulted));

    // V00.73: apply audit sub-builder state (no-op when .audit(...) wasn't called).
    applyAuditConfiguration(services, warnings);
    // V00.73: apply sessions sub-builder state. REST consumes Policy/Version/Resolver;
    // .storeBacked(...) emits rest/session-store-unused (INFO).
    applySessionConfiguration(AdapterKind.REST, services, warnings);

    SecurityBootstrapMode mode = state.mode();
    if (mode == SecurityBootstrapMode.STRICT && warningsContainError(warnings)) {
      throw new SecurityBootstrapException(warnings);
    }

    return new SecurityRuntime(services, warnings, mode);
  }
}
