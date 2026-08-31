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
package eu.jsentinel.jcustos.identity.oidc;

import eu.jsentinel.jcustos.oidc.api.LogoutInitiator;
import eu.jsentinel.jcustos.oidc.api.LogoutRequest;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Builds the OIDC RP-Initiated Logout 1.0 redirect URL (V00.78): the
 * {@code end_session_endpoint} with {@code id_token_hint} +
 * {@code post_logout_redirect_uri} + {@code state}, all percent-encoded. Pure URL
 * construction — no network call. The {@code end_session_endpoint} comes from
 * discovery / trusted configuration (never user input), and the OP matches the
 * {@code post_logout_redirect_uri} against its registered set, so the RP side
 * introduces no open-redirect.
 */
public final class RpInitiatedLogoutInitiator implements LogoutInitiator {

  @Override
  public URI buildLogoutUri(URI endSessionEndpoint, LogoutRequest request) {
    Objects.requireNonNull(endSessionEndpoint, "endSessionEndpoint");
    Objects.requireNonNull(request, "request");
    StringBuilder query = new StringBuilder();
    append(query, "id_token_hint", request.idTokenHint());
    request.postLogoutRedirectUri()
        .ifPresent(uri -> append(query, "post_logout_redirect_uri", uri.toString()));
    request.state().ifPresent(state -> append(query, "state", state));

    String separator = endSessionEndpoint.getRawQuery() == null ? "?" : "&";
    return URI.create(endSessionEndpoint + separator + query);
  }

  private static void append(StringBuilder query, String key, String value) {
    if (query.length() > 0) {
      query.append('&');
    }
    query.append(URLEncoder.encode(key, StandardCharsets.UTF_8))
        .append('=')
        .append(URLEncoder.encode(value, StandardCharsets.UTF_8));
  }
}
