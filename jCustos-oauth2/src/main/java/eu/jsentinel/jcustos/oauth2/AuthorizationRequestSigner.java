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
package eu.jsentinel.jcustos.oauth2;

/*-
 * #%L
 * jCustos OAuth2 — RP flows (token endpoint, auth-code, refresh, device)
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 * 
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * 
 * http://ec.europa.eu/idabc/eupl5
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.jwt.api.JwtSigner;
import eu.jsentinel.jcustos.jwt.api.JwtSigningKey;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Builds a JWT-Secured Authorization Request object (V00.79, RFC 9101 §3): the
 * authorization-request parameters are signed into a JWT (the {@code request} object) so
 * the authorization server can verify integrity + authenticity before the user-agent is
 * involved. Reuses the V00.77 {@link JwtSigner} SPI — the request object is signed with
 * the asymmetric, allow-listed algorithm of {@link JwtSigningKey} (never {@code none}).
 * Per §3 the JWT carries {@code iss = client_id} and {@code aud = }authorization-server.
 *
 * @since 00.79.20
 */
@ExperimentalJCustosApi
public final class AuthorizationRequestSigner {

  private final JwtSigner signer;
  private final JwtSigningKey key;
  private final String clientId;

  public AuthorizationRequestSigner(JwtSigner signer, JwtSigningKey key, String clientId) {
    this.signer = Objects.requireNonNull(signer, "signer");
    this.key = Objects.requireNonNull(key, "key");
    this.clientId = Objects.requireNonNull(clientId, "clientId");
    if (clientId.isBlank()) {
      throw new IllegalArgumentException("clientId must not be blank");
    }
  }

  /**
   * Signs {@code authorizationRequestParams} into a compact JWS {@code request} object
   * for {@code audience} (the authorization server's issuer identifier).
   */
  public String sign(Map<String, String> authorizationRequestParams, String audience) {
    Objects.requireNonNull(authorizationRequestParams, "authorizationRequestParams");
    Objects.requireNonNull(audience, "audience");
    Map<String, Object> claims = new LinkedHashMap<>(authorizationRequestParams);
    claims.put("iss", clientId);
    claims.put("aud", audience);
    claims.put("client_id", clientId);
    return signer.sign(claims, key);
  }
}
