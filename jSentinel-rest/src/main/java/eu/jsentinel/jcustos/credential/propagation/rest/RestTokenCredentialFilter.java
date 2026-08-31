/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.credential.propagation.rest;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.credential.propagation.BearerToken;
import eu.jsentinel.jcustos.credential.propagation.TokenCredentialStore;
import eu.jsentinel.jcustos.rest.BearerTokenExtractor;
import eu.jsentinel.jcustos.rest.RestRequest;

import java.util.Objects;
import java.util.Optional;

/**
 * Request-scope filter that binds the inbound Bearer token into a
 * {@link TokenCredentialStore} and clears it in the {@code finally}
 * block. Wire <strong>after</strong>
 * {@code RestJCustosVersionFilter} but <strong>before</strong> the
 * authorization filter / handler so the credential is available to the
 * handler and downstream propagating wrappers.
 *
 * <p>Pattern parallel to {@code RestJCustosVersionFilter}.
 *
 * @since 00.74.00
 */
@ExperimentalJCustosApi
public final class RestTokenCredentialFilter {

  private final BearerTokenExtractor extractor = new BearerTokenExtractor();
  private final TokenCredentialStore store;

  /**
   * @param store the credential store to bind into; non-null
   */
  public RestTokenCredentialFilter(TokenCredentialStore store) {
    this.store = Objects.requireNonNull(store, "store");
  }

  /**
   * Binds the Bearer token (if any) and runs the supplied handler. The
   * slot is cleared regardless of how the handler returns — normal or
   * exceptional.
   *
   * @param request the incoming request
   * @param handler the downstream work to run
   */
  public void runWithCredential(RestRequest request, Runnable handler) {
    Objects.requireNonNull(request, "request");
    Objects.requireNonNull(handler, "handler");
    Optional<String> bearer = extractor.extract(request);
    bearer.ifPresent(value -> store.bind(new BearerToken(value)));
    try {
      handler.run();
    } finally {
      store.clear();
    }
  }
}
