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

import com.svenruppert.jsentinel.authorization.api.AuthorizationDecision;
import com.svenruppert.jsentinel.rest.HttpStatusDecisionMapper;
import com.svenruppert.jsentinel.rest.RestResponse;

/**
 * Default {@link RestDecisionMapper} that delegates to the existing
 * {@link HttpStatusDecisionMapper}.
 *
 * @since 00.72.00
 */
public final class DefaultRestDecisionMapper implements RestDecisionMapper {

  private final HttpStatusDecisionMapper delegate = new HttpStatusDecisionMapper();

  @Override
  public boolean apply(AuthorizationDecision decision, RestResponse response) {
    return delegate.apply(decision, response);
  }
}
