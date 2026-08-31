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
package eu.jsentinel.jcustos.dx.rest.bootstrap;

import eu.jsentinel.jcustos.dx.bootstrap.CommonJSentinelBootstrap;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;

import java.util.function.Consumer;

/**
 * REST-specific fluent bootstrap. Entry point:
 * {@link RestSecurity#bootstrap()}.
 *
 * @since 00.72.00
 */
public interface RestJSentinelBootstrap
    extends CommonJSentinelBootstrap<RestJSentinelBootstrap> {

  RestJSentinelBootstrap subjectResolver(RestSubjectResolver resolver);

  RestJSentinelBootstrap decisionMapper(RestDecisionMapper mapper);

  RestJSentinelBootstrap errorBodies(RestErrorBodyStrategy strategy);

  /**
   * V00.74: Convenience for
   * {@code .errorBodies(ProblemJsonErrorBodyStrategy.INSTANCE)} —
   * emits RFC 7807 {@code application/problem+json} bodies for
   * denial decisions.
   *
   * @return this builder
   * @since 00.74.00
   */
  default RestJSentinelBootstrap problemJsonErrors() {
    return errorBodies(ProblemJsonErrorBodyStrategy.INSTANCE);
  }

  /**
   * V00.74: Configures CORS for the REST adapter. The published
   * {@link RestCorsConfiguration} is consumed by downstream REST
   * glue (a servlet filter, embedded server, etc.) — the library
   * does not ship a CORS filter itself.
   *
   * @param consumer non-null consumer that configures the
   *                 {@link RestCorsConfigurationBuilder}
   * @return this builder
   * @since 00.74.00
   */
  RestJSentinelBootstrap cors(Consumer<RestCorsConfigurationBuilder> consumer);

  /**
   * V00.74: Configures OpenAPI document metadata
   * ({@code Info.title} / {@code Info.version} /
   * {@code Info.description} / {@code servers[]}). The published
   * {@link RestOpenApiMetadata} is consumed by
   * {@code OpenApiSecurityMetadataGenerator} at document-generation
   * time.
   *
   * @param consumer non-null consumer that configures the
   *                 {@link RestOpenApiMetadataBuilder}
   * @return this builder
   * @since 00.74.00
   */
  RestJSentinelBootstrap openApiMetadata(Consumer<RestOpenApiMetadataBuilder> consumer);
}
