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
public interface RestDecisionMapper {

  /**
   * Applies the decision to the response.
   *
   * @param decision decision
   * @param response response
   * @return {@code true} if the protected handler may continue
   */
  boolean apply(AuthorizationDecision decision, RestResponse response);
}
