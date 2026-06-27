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

import com.svenruppert.functional.result.Result;
import com.svenruppert.jsentinel.oauth2.api.OAuth2Error;

import java.net.URI;

/**
 * Fetches OIDC provider metadata from {@code <issuer>/.well-known/openid-configuration}
 * (OIDC Discovery 1.0 / RFC 8414, V00.78). The HTTP implementation
 * ({@code jSentinel-identity-oidc}) caches the result with a TTL and validates that
 * the returned {@code issuer} matches the requested one. Reuses the OAuth2 transport
 * error type ({@link OAuth2Error}) — JOSE-free contract.
 *
 * @since 00.78.00
 */
public interface OidcDiscoveryClient {

  /**
   * Discovers the provider metadata for {@code issuer}.
   *
   * @param issuer the issuer base URI (the well-known path is appended)
   * @return the provider metadata, or a non-secret {@link OAuth2Error}
   */
  Result<OidcProviderMetadata, OAuth2Error> discover(URI issuer);
}
