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

import eu.jsentinel.jcustos.dx.bootstrap.CommonJCustosBootstrap;
import eu.jsentinel.jcustos.rest.RestSubjectResolver;

import java.util.function.Consumer;
import eu.jsentinel.jcustos.dx.rest.handlers.RestHandlerDiscovery;

/**
 * REST-specific fluent bootstrap. Entry point:
 * {@link RestSecurity#bootstrap()}.
 *
 * @since 00.72.00
 */
public interface RestJCustosBootstrap
    extends CommonJCustosBootstrap<RestJCustosBootstrap> {

  RestJCustosBootstrap subjectResolver(RestSubjectResolver resolver);

  RestJCustosBootstrap decisionMapper(RestDecisionMapper mapper);

  RestJCustosBootstrap errorBodies(RestErrorBodyStrategy strategy);

  /**
   * V00.74: Convenience for
   * {@code .errorBodies(ProblemJsonErrorBodyStrategy.INSTANCE)} —
   * emits RFC 7807 {@code application/problem+json} bodies for
   * denial decisions.
   *
   * @return this builder
   * @since 00.74.00
   */
  default RestJCustosBootstrap problemJsonErrors() {
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
  RestJCustosBootstrap cors(Consumer<RestCorsConfigurationBuilder> consumer);

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
  RestJCustosBootstrap openApiMetadata(Consumer<RestOpenApiMetadataBuilder> consumer);

  /**
   * V00.82: Registers the handler enumeration used for the deny-by-default
   * startup check (CWE-862).
   *
   * <p>With deny-by-default on, a handler carrying no security annotation is
   * refused at runtime. That is the right outcome, but a REST application only
   * discovered it when a request arrived — Vaadin reports it at startup because
   * its router can enumerate routes, and REST has no such registry. Naming your
   * handler classes here restores the startup check:
   *
   * <pre>{@code
   * RestSecurity.bootstrap()
   *     .discoverHandlers(new ClassScanningRestHandlerDiscovery(DocumentHandlers.class))
   *     .mode(JCustosBootstrapMode.STRICT)
   *     .install();
   * }</pre>
   *
   * <p>Each unprotected handler becomes an ERROR finding, so STRICT refuses to
   * boot rather than serving an unguarded endpoint. Without deny-by-default the
   * enumeration is not consulted at all.
   *
   * @param discovery non-null enumeration of the application's handlers
   * @return this builder
   * @since 00.82.00
   */
  RestJCustosBootstrap discoverHandlers(RestHandlerDiscovery discovery);
}
