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

import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;

/**
 * Default {@link RestErrorBodyStrategy} returning the generic terse
 * strings used by the existing {@code HttpStatusDecisionMapper}.
 *
 * @since 00.72.00
 */
public final class DefaultRestErrorBodyStrategy implements RestErrorBodyStrategy {

  @Override
  public String bodyFor(AuthorizationDecision decision) {
    return switch (decision) {
      case AuthorizationDecision.Granted ignored -> "";
      case AuthorizationDecision.Unauthenticated ignored -> "Unauthorized";
      case AuthorizationDecision.Forbidden ignored -> "Forbidden";
      case AuthorizationDecision.StepUpRequired ignored -> "Unauthorized";
    };
  }
}
