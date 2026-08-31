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

/*-
 * #%L
 * jCustos OIDC — Relying-Party identity layer
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.oidc.api.LogoutInitiator;
import eu.jsentinel.jcustos.oidc.api.LogoutRequest;
import eu.jsentinel.jcustos.oidc.api.PostLogoutRedirectValidator;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Builds the OIDC RP-Initiated Logout 1.0 redirect URL (V00.78): the
 * {@code end_session_endpoint} with {@code id_token_hint} +
 * {@code post_logout_redirect_uri} + {@code state}, all percent-encoded. Pure URL
 * construction — no network call. The {@code end_session_endpoint} comes from
 * discovery / trusted configuration, never from user input.
 *
 * <p>The {@code post_logout_redirect_uri} is a different matter. The provider
 * matches it against its registered set, which is the primary defence — but
 * that check happens somewhere this code cannot see, and if the URI came from
 * the incoming request, an attacker chooses where the user lands after logout
 * (CWE-601). Pass a {@link PostLogoutRedirectValidator} to state locally where
 * logout may lead; the default keeps the pre-00.82 behaviour of forwarding
 * whatever it is given.
 */
public final class RpInitiatedLogoutInitiator implements LogoutInitiator {

  private final PostLogoutRedirectValidator redirectValidator;

  /** Forwards any redirect URI — the behaviour of releases before 00.82.00. */
  public RpInitiatedLogoutInitiator() {
    this(PostLogoutRedirectValidator.permitAll());
  }

  /**
   * @param redirectValidator decides which {@code post_logout_redirect_uri}
   *                          values may be sent, never {@code null}
   * @since 00.82.00
   */
  public RpInitiatedLogoutInitiator(PostLogoutRedirectValidator redirectValidator) {
    this.redirectValidator =
        Objects.requireNonNull(redirectValidator, "redirectValidator must not be null");
  }

  @Override
  public URI buildLogoutUri(URI endSessionEndpoint, LogoutRequest request) {
    Objects.requireNonNull(endSessionEndpoint, "endSessionEndpoint");
    Objects.requireNonNull(request, "request");
    StringBuilder query = new StringBuilder();
    append(query, "id_token_hint", request.idTokenHint());
    request.postLogoutRedirectUri().ifPresent(uri -> {
      if (!redirectValidator.isAllowed(uri)) {
        // Refuse rather than drop it: a rejected URI means either an attack or a
        // misconfigured allowlist, and silently logging the user out to the
        // provider's default page would hide both.
        throw new IllegalArgumentException(
            "post_logout_redirect_uri is not allowed: " + uri
                + " — add it to the validator's allowlist if this target is intended");
      }
      append(query, "post_logout_redirect_uri", uri.toString());
    });
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
