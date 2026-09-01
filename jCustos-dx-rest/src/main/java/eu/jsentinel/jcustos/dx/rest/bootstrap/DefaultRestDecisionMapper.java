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
 * Default {@link RestDecisionMapper} that delegates to the existing
 * {@link HttpStatusDecisionMapper}.
 *
 * <p>Since V00.83 it hands the configured {@link RestErrorBodyStrategy}
 * to that delegate. Before, the two defaults merely happened to agree
 * and a custom body strategy was inert (JS-SEC-026).
 *
 * @since 00.72.00
 */
public final class DefaultRestDecisionMapper implements RestDecisionMapper {

  private final HttpStatusDecisionMapper delegate;

  /** Uses the generic default bodies. */
  public DefaultRestDecisionMapper() {
    this.delegate = new HttpStatusDecisionMapper();
  }

  /**
   * @param errorBodies the body strategy to render denials with (non-null)
   * @since 00.83.00
   */
  public DefaultRestDecisionMapper(RestErrorBodyStrategy errorBodies) {
    this.delegate = new HttpStatusDecisionMapper(
        java.util.Objects.requireNonNull(errorBodies, "errorBodies"));
  }

  @Override
  public boolean apply(AuthorizationDecision decision, RestResponse response) {
    return delegate.apply(decision, response);
  }
}
