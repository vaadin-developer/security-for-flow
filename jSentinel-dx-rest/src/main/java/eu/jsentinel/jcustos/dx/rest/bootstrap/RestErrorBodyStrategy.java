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

/**
 * Strategy for the error body returned on denied REST responses.
 * Implementations must return generic strings only — no stack traces,
 * no internal classifications, no subject/credential information.
 * <p>
 * The {@link DefaultRestErrorBodyStrategy default} returns
 * {@code "Unauthorized"}, {@code "Forbidden"} and similar terse
 * strings per RFC 9110.
 *
 * @since 00.72.00
 */
@FunctionalInterface
public interface RestErrorBodyStrategy {

  /**
   * @param decision the denial decision
   * @return the body string, never {@code null}
   */
  String bodyFor(AuthorizationDecision decision);
}
