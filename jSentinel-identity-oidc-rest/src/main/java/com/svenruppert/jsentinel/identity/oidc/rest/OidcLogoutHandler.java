/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.identity.oidc.rest;

import com.svenruppert.jsentinel.identity.oidc.RpInitiatedLogoutInitiator;
import com.svenruppert.jsentinel.oidc.api.LogoutInitiator;
import com.svenruppert.jsentinel.oidc.api.LogoutRequest;
import com.svenruppert.jsentinel.rest.RestHandler;
import com.svenruppert.jsentinel.rest.RestRequest;
import com.svenruppert.jsentinel.rest.RestResponse;

import java.net.URI;
import java.util.Objects;
import java.util.function.Function;

/**
 * The REST-side OIDC RP-initiated-logout handler (V00.78). Builds the
 * {@code end_session_endpoint} redirect via {@link LogoutInitiator} and replies
 * {@code 302} with a {@code Location} header. The current session's
 * {@code id_token_hint} is supplied by a consumer-provided resolver (the handler
 * does not read tokens from the request itself), and the local session teardown is
 * the consumer's responsibility before/around this redirect.
 */
public final class OidcLogoutHandler implements RestHandler {

  /** Resolves the OIDC logout parameters for the current request (id_token_hint, …). */
  @FunctionalInterface
  public interface LogoutRequestResolver {
    LogoutRequest resolve(RestRequest request);
  }

  private final URI endSessionEndpoint;
  private final LogoutInitiator initiator;
  private final LogoutRequestResolver resolver;

  public OidcLogoutHandler(URI endSessionEndpoint, LogoutRequestResolver resolver) {
    this(endSessionEndpoint, new RpInitiatedLogoutInitiator(), resolver);
  }

  public OidcLogoutHandler(URI endSessionEndpoint, LogoutInitiator initiator,
      LogoutRequestResolver resolver) {
    this.endSessionEndpoint = Objects.requireNonNull(endSessionEndpoint, "endSessionEndpoint");
    this.initiator = Objects.requireNonNull(initiator, "initiator");
    this.resolver = Objects.requireNonNull(resolver, "resolver");
  }

  @Override
  public void handle(RestRequest request, RestResponse response) {
    LogoutRequest logout = resolver.resolve(request);
    URI redirect = initiator.buildLogoutUri(endSessionEndpoint, logout);
    response.status(302);
    response.header("Location", redirect.toString());
  }

  /** Convenience resolver: a constant id_token_hint source from the request. */
  public static LogoutRequestResolver hintFrom(Function<RestRequest, String> idTokenHint,
      URI postLogoutRedirectUri) {
    Objects.requireNonNull(idTokenHint, "idTokenHint");
    return request -> new LogoutRequest(idTokenHint.apply(request),
        java.util.Optional.ofNullable(postLogoutRedirectUri), java.util.Optional.empty());
  }
}
