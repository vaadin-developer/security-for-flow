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
package eu.jsentinel.jcustos.oauth2.api;

import java.time.Instant;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * A successful OAuth2 token-endpoint response (RFC 6749 §5.1, V00.77).
 *
 * <p>The {@code idToken} slot is reached through but <strong>not validated</strong>
 * in V00.77 — OIDC ID-token semantics are V00.78. {@link #toString()} masks the
 * {@code access_token} / {@code refresh_token} / {@code id_token} values so they
 * never leak into a log line.
 *
 * @param accessToken  the bearer access token (opaque or JWT)
 * @param refreshToken the refresh token, if issued
 * @param idToken      the OIDC ID token, if present (unvalidated in V00.77)
 * @param tokenType    the token type (almost always {@code "Bearer"})
 * @param expiresAt    absolute access-token expiry, if {@code expires_in} was present
 * @param scopes       the granted scopes
 * @since 00.77.00
 */
public record TokenResponse(
    String accessToken,
    Optional<String> refreshToken,
    Optional<String> idToken,
    String tokenType,
    Optional<Instant> expiresAt,
    Set<String> scopes) {

  public TokenResponse {
    Objects.requireNonNull(accessToken, "accessToken");
    Objects.requireNonNull(refreshToken, "refreshToken");
    Objects.requireNonNull(idToken, "idToken");
    Objects.requireNonNull(tokenType, "tokenType");
    Objects.requireNonNull(expiresAt, "expiresAt");
    scopes = Set.copyOf(Objects.requireNonNull(scopes, "scopes"));
  }

  @Override
  public String toString() {
    return "TokenResponse[accessToken=***"
        + ", refreshToken=" + (refreshToken.isPresent() ? "***" : "<none>")
        + ", idToken=" + (idToken.isPresent() ? "***" : "<none>")
        + ", tokenType=" + tokenType
        + ", expiresAt=" + expiresAt.map(Instant::toString).orElse("<none>")
        + ", scopes=" + scopes + "]";
  }
}
