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

import java.net.URI;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The resolved OAuth2 RP configuration (V00.77) — the immutable snapshot the
 * {@code jSentinel-oauth2} factory turns into the HTTP clients + flow. The
 * {@code .oauth2(...)} bootstrap sub-builder produces it.
 *
 * @param clientAuth                 how the RP authenticates (carries the client id)
 * @param authorizationEndpoint      the authorization endpoint, for the auth-code flow
 * @param tokenEndpoint              the token endpoint (mandatory)
 * @param revocationEndpoint         the revocation endpoint, if configured
 * @param introspectionEndpoint      the introspection endpoint, if configured
 * @param deviceAuthorizationEndpoint the device-authorization endpoint, if configured
 * @param redirectUri                the RP redirect URI, for the auth-code flow
 * @param scopes                     the requested scopes
 * @param pkceRequired               whether PKCE is required (default true)
 * @param refreshTokenRotation       whether to rotate refresh tokens (default true)
 * @param stateTtl                   the authorization-state TTL
 * @since 00.77.00
 */
public record OAuth2ClientConfig(
    ClientAuthentication clientAuth,
    Optional<URI> authorizationEndpoint,
    URI tokenEndpoint,
    Optional<URI> revocationEndpoint,
    Optional<URI> introspectionEndpoint,
    Optional<URI> deviceAuthorizationEndpoint,
    Optional<URI> redirectUri,
    Set<String> scopes,
    boolean pkceRequired,
    boolean refreshTokenRotation,
    Duration stateTtl) {

  public OAuth2ClientConfig {
    Objects.requireNonNull(clientAuth, "clientAuth");
    Objects.requireNonNull(authorizationEndpoint, "authorizationEndpoint");
    Objects.requireNonNull(tokenEndpoint, "tokenEndpoint");
    Objects.requireNonNull(revocationEndpoint, "revocationEndpoint");
    Objects.requireNonNull(introspectionEndpoint, "introspectionEndpoint");
    Objects.requireNonNull(deviceAuthorizationEndpoint, "deviceAuthorizationEndpoint");
    Objects.requireNonNull(redirectUri, "redirectUri");
    scopes = Set.copyOf(Objects.requireNonNull(scopes, "scopes"));
    Objects.requireNonNull(stateTtl, "stateTtl");
  }

  /** @return the OAuth2 {@code client_id} from {@link #clientAuth()}. */
  public String clientId() {
    return clientAuth.clientId();
  }
}
