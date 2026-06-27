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
package com.svenruppert.jsentinel.oauth2.api;

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.credential.secret.SecretValue;

import java.net.URI;
import java.util.Set;

/**
 * The OAuth2 token endpoint (RFC 6749 §3.2, V00.77) — the RP's lifeline. The
 * JOSE-free contract; the {@code jSentinel-oauth2} HTTP implementation handles
 * client authentication, the form body and response parsing. Every method
 * returns a {@link Result} carrying a {@link TokenResponse} or a non-secret
 * {@link OAuth2Error}.
 *
 * @since 00.77.00
 */
public interface TokenEndpointClient {

  /** Authorization-code grant (RFC 6749 §4.1.3) with the PKCE verifier. */
  Result<TokenResponse, OAuth2Error> exchangeCode(String code, URI redirectUri, PkceVerifier pkce);

  /** Refresh-token grant (RFC 6749 §6); rotation/reuse-detection is applied by the flow. */
  Result<TokenResponse, OAuth2Error> refresh(SecretValue refreshToken);

  /** Client-credentials grant (RFC 6749 §4.4) for service-to-service. */
  Result<TokenResponse, OAuth2Error> clientCredentials(Set<String> scopes);

  /** Device-access-token grant (RFC 8628 §3.4) — a single poll against the token endpoint. */
  Result<TokenResponse, OAuth2Error> deviceToken(String deviceCode);
}
