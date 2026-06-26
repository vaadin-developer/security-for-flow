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
import java.util.Set;

/**
 * OIDC provider metadata from {@code .well-known/openid-configuration} (OIDC
 * Discovery 1.0 / RFC 8414, V00.78). Carries the endpoints + capabilities a
 * Relying-Party needs to wire its OAuth2 + OIDC clients. {@code issuer},
 * {@code authorizationEndpoint}, {@code tokenEndpoint} and {@code jwksUri} are
 * mandatory per spec; the rest are optional.
 *
 * @since 00.78.00
 */
@ExperimentalJSentinelApi
public record OidcProviderMetadata(
    String issuer,
    URI authorizationEndpoint,
    URI tokenEndpoint,
    URI jwksUri,
    Optional<URI> userinfoEndpoint,
    Optional<URI> endSessionEndpoint,
    Optional<URI> introspectionEndpoint,
    Optional<URI> revocationEndpoint,
    Optional<URI> deviceAuthorizationEndpoint,
    Set<String> scopesSupported,
    Set<String> responseTypesSupported,
    Set<String> idTokenSigningAlgValuesSupported) {

  public OidcProviderMetadata {
    Objects.requireNonNull(issuer, "issuer");
    Objects.requireNonNull(authorizationEndpoint, "authorizationEndpoint");
    Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
    Objects.requireNonNull(jwksUri, "jwksUri");
    Objects.requireNonNull(userinfoEndpoint, "userinfoEndpoint");
    Objects.requireNonNull(endSessionEndpoint, "endSessionEndpoint");
    Objects.requireNonNull(introspectionEndpoint, "introspectionEndpoint");
    Objects.requireNonNull(revocationEndpoint, "revocationEndpoint");
    Objects.requireNonNull(deviceAuthorizationEndpoint, "deviceAuthorizationEndpoint");
    scopesSupported = Set.copyOf(Objects.requireNonNull(scopesSupported, "scopesSupported"));
    responseTypesSupported =
        Set.copyOf(Objects.requireNonNull(responseTypesSupported, "responseTypesSupported"));
    idTokenSigningAlgValuesSupported = Set.copyOf(
        Objects.requireNonNull(idTokenSigningAlgValuesSupported, "idTokenSigningAlgValuesSupported"));
  }
}
