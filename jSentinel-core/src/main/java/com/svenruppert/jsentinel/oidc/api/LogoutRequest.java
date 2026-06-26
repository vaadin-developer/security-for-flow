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
package com.svenruppert.jsentinel.oidc.api;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

/**
 * The parameters for an OIDC RP-Initiated Logout 1.0 request (V00.78). The
 * {@code id_token_hint} lets the OP identify the session; the
 * {@code post_logout_redirect_uri} (which the OP matches against its registered
 * set) is where the user returns afterwards; {@code state} round-trips for CSRF
 * protection on the return.
 *
 * @param idTokenHint           the ID token previously issued to this session (never logged)
 * @param postLogoutRedirectUri where the OP should redirect after logout, if any
 * @param state                 an opaque value echoed back on the redirect, if any
 * @since 00.78.00
 */
@ExperimentalJSentinelApi
public record LogoutRequest(
    String idTokenHint,
    Optional<URI> postLogoutRedirectUri,
    Optional<String> state) {

  public LogoutRequest {
    Objects.requireNonNull(idTokenHint, "idTokenHint");
    Objects.requireNonNull(postLogoutRedirectUri, "postLogoutRedirectUri");
    Objects.requireNonNull(state, "state");
  }

  /** @return a string that masks the id_token_hint (a credential). */
  @Override
  public String toString() {
    return "LogoutRequest[idTokenHint=***, postLogoutRedirectUri=" + postLogoutRedirectUri
        + ", state=" + state + "]";
  }
}
