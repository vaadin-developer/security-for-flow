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

import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.rest.HttpStatusDecisionMapper;
import eu.jsentinel.jcustos.rest.RestResponse;

/**
 * Functional bridge that maps a semantic
 * {@link AuthorizationDecision} onto a {@link RestResponse}. The default
 * implementation in {@link DefaultRestDecisionMapper} delegates to the
 * existing {@link HttpStatusDecisionMapper}; consumers may supply a
 * custom mapping (e.g. structured RFC 7807 problem+json bodies in a
 * future module).
 *
 * @since 00.72.00
 */
@FunctionalInterface
public interface RestDecisionMapper extends
    eu.jsentinel.jcustos.rest.RestDecisionMapping {

  /**
   * Applies the decision to the response.
   *
   * <p>Since V00.83 this is the inherited
   * {@code RestDecisionMapping.apply} — the enforcing filter accepts the
   * supertype, so a mapper configured here now actually reaches it
   * (JS-SEC-026). Existing lambdas and implementations are unaffected.
   *
   * @param decision decision
   * @param response response
   * @return {@code true} if the protected handler may continue
   */
  @Override
  boolean apply(AuthorizationDecision decision, RestResponse response);
}
