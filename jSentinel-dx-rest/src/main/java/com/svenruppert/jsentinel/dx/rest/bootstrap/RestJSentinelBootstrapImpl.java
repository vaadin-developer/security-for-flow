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
package com.svenruppert.jsentinel.dx.rest.bootstrap;

import com.svenruppert.jsentinel.authentication.AuthenticationService;
import com.svenruppert.jsentinel.authorization.api.AuthorizationService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.dx.bootstrap.JSentinelBootstrapException;
import com.svenruppert.jsentinel.dx.internal.AbstractJSentinelBootstrap;
import com.svenruppert.jsentinel.dx.runtime.RegisteredJSentinelService;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapMode;
import com.svenruppert.jsentinel.dx.runtime.JSentinelBootstrapWarning;
import com.svenruppert.jsentinel.dx.runtime.JSentinelRuntime;
import com.svenruppert.jsentinel.dx.runtime.Severity;
import com.svenruppert.jsentinel.rest.RestSubjectResolver;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Package-private implementation of {@link RestJSentinelBootstrap}.
 *
 * @since 00.72.00
 */
final class RestJSentinelBootstrapImpl
    extends AbstractJSentinelBootstrap<RestJSentinelBootstrap>
    implements RestJSentinelBootstrap {

  private RestSubjectResolver subjectResolver;
  private RestDecisionMapper decisionMapper;
  private RestErrorBodyStrategy errorBodies;
  private RestCorsConfiguration corsConfiguration;
  private RestOpenApiMetadata openApiMetadata;
  private boolean installed;

  @Override
  public RestJSentinelBootstrap subjectResolver(RestSubjectResolver resolver) {
    this.subjectResolver = Objects.requireNonNull(resolver, "resolver");
    return this;
  }

  @Override
  public RestJSentinelBootstrap decisionMapper(RestDecisionMapper mapper) {
    this.decisionMapper = Objects.requireNonNull(mapper, "mapper");
    return this;
  }

  @Override
  public RestJSentinelBootstrap errorBodies(RestErrorBodyStrategy strategy) {
    this.errorBodies = Objects.requireNonNull(strategy, "strategy");
    return this;
  }

  @Override
  public RestJSentinelBootstrap cors(Consumer<RestCorsConfigurationBuilder> consumer) {
    Objects.requireNonNull(consumer, "consumer");
    RestCorsConfigurationBuilder builder = new RestCorsConfigurationBuilder();
    consumer.accept(builder);
    this.corsConfiguration = builder.toConfiguration();
    return this;
  }

  @Override
  public RestJSentinelBootstrap openApiMetadata(Consumer<RestOpenApiMetadataBuilder> consumer) {
    Objects.requireNonNull(consumer, "consumer");
    RestOpenApiMetadataBuilder builder = new RestOpenApiMetadataBuilder();
    consumer.accept(builder);
    this.openApiMetadata = builder.toMetadata();
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
          "No AuthenticationService configured for RestSecurity.bootstrap().",
          "Call .authentication(...) or register an implementation via "
              + "@JSentinelAutoService(AuthenticationService.class)."));
    }

    if (authz != null) {
      JSentinelServiceResolver.setAuthorizationService(authz);
      services.add(new RegisteredJSentinelService(
          AuthorizationService.class, authz.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new JSentinelBootstrapWarning(
          Severity.ERROR,
          "missing-authorization-service",
          "No AuthorizationService configured for RestSecurity.bootstrap().",
          "Call .authorization(...) or register an implementation via "
              + "@JSentinelAutoService(AuthorizationService.class)."));
    }

    if (subjectResolver != null) {
      services.add(new RegisteredJSentinelService(
          RestSubjectResolver.class, subjectResolver.getClass(), "bootstrap-explicit", false));
    } else {
      warnings.add(new JSentinelBootstrapWarning(
          Severity.ERROR,
          "missing-rest-subject-resolver",
          "No RestSubjectResolver configured for RestSecurity.bootstrap().",
          "Call .subjectResolver(...) or register an implementation via "
              + "@JSentinelAutoService(RestSubjectResolver.class)."));
    }

    RestDecisionMapper effectiveDecisionMapper = decisionMapper;
    boolean decisionMapperDefaulted = false;
    if (effectiveDecisionMapper == null) {
      effectiveDecisionMapper = new DefaultRestDecisionMapper();
      decisionMapperDefaulted = true;
    }
    services.add(new RegisteredJSentinelService(
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
    services.add(new RegisteredJSentinelService(
        RestErrorBodyStrategy.class,
        effectiveErrorBodies.getClass(),
        errorBodiesDefaulted ? "bootstrap-default" : "bootstrap-explicit",
        errorBodiesDefaulted));

    // V00.74: apply direct-set services from CommonJSentinelBootstrap
    // (logout / bruteForce / rateLimit / apiKeys / refreshTokens).
    applyDirectServiceConfiguration(services, warnings);
    // V00.73: apply audit sub-builder state (no-op when .audit(...) wasn't called).
    applyAuditConfiguration(services, warnings);
    // V00.73: apply sessions sub-builder state. REST consumes Policy/Version/Resolver;
    // .storeBacked(...) emits rest/session-store-unused (INFO).
    applySessionConfiguration(AdapterKind.REST, services, warnings);
    // V00.73: apply roles sub-builder state.
    applyRoleConfiguration(services, warnings);
    // V00.73: apply credentials sub-builder state.
    applyCredentialConfiguration(services, warnings);
    // V00.73: apply policies sub-builder state.
    applyPolicyConfiguration(services, warnings);
    // V00.74: apply propagation sub-builder state.
    applyPropagationConfiguration(services, warnings);

    // V00.74 (A2.2): publish CORS configuration when configured.
    if (corsConfiguration != null) {
      RestCorsContext.publish(corsConfiguration);
      services.add(new RegisteredJSentinelService(
          RestCorsContext.class, RestCorsConfiguration.class,
          "bootstrap-cors", false));
    }
    // V00.74 (A2.2): publish OpenAPI metadata when configured.
    if (openApiMetadata != null) {
      RestOpenApiContext.publish(openApiMetadata);
      services.add(new RegisteredJSentinelService(
          RestOpenApiContext.class, RestOpenApiMetadata.class,
          "bootstrap-openapi-metadata", false));
    }

    JSentinelBootstrapMode mode = state.mode();
    if (mode == JSentinelBootstrapMode.STRICT && warningsContainError(warnings)) {
      throw new JSentinelBootstrapException(warnings);
    }

    return new JSentinelRuntime(services, warnings, mode);
  }
}
