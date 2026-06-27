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

import com.svenruppert.jsentinel.jwt.api.ValidatedJwt;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A validated OIDC ID token (V00.78) — the JWT-standard claims plus the OIDC
 * authentication-context claims that drove the validation. The wrapped
 * {@link ValidatedJwt} carries all raw claims; the typed fields surface the OIDC
 * claims that the {@code IdTokenValidator} pipeline checked ({@code nonce},
 * {@code auth_time}, {@code acr}, {@code amr}, {@code azp}, {@code session_state}).
 *
 * @param jwt              the validated JWT (standard claims + raw map)
 * @param nonce            the {@code nonce} claim, if present (checked against the request)
 * @param authTime         the {@code auth_time} claim, if present (for {@code max_age} step-up)
 * @param acr              the {@code acr} authentication-context-class, if present
 * @param amr              the {@code amr} authentication-methods (never null; possibly empty)
 * @param authorizedParty  the {@code azp} claim, if present
 * @param sessionState     the {@code session_state} claim, if present
 * @since 00.78.00
 */
public record ValidatedIdToken(
    ValidatedJwt jwt,
    Optional<String> nonce,
    Optional<Instant> authTime,
    Optional<String> acr,
    List<String> amr,
    Optional<String> authorizedParty,
    Optional<String> sessionState) {

  public ValidatedIdToken {
    Objects.requireNonNull(jwt, "jwt");
    Objects.requireNonNull(nonce, "nonce");
    Objects.requireNonNull(authTime, "authTime");
    Objects.requireNonNull(acr, "acr");
    amr = List.copyOf(Objects.requireNonNull(amr, "amr"));
    Objects.requireNonNull(authorizedParty, "authorizedParty");
    Objects.requireNonNull(sessionState, "sessionState");
  }

  /** @return the {@code sub} (subject) claim. */
  public Optional<String> subject() {
    return jwt.subject();
  }

  /** @return the {@code iss} (issuer) claim. */
  public Optional<String> issuer() {
    return jwt.issuer();
  }
}
