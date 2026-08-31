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
package eu.jsentinel.jcustos.oidc.api;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

import java.util.Objects;
import java.util.Optional;

/**
 * A validated OIDC Back-Channel Logout token (V00.79) — the subset of claims a relying
 * party acts on after the token has passed signature + issuer + audience + event
 * validation (OpenID Connect Back-Channel Logout 1.0 §2.4). At least one of
 * {@code subject} / {@code sid} is always present; the RP uses them to find the
 * sessions to terminate.
 *
 * @since 00.79.10
 */
@ExperimentalJCustosApi
public record BackChannelLogoutToken(
    String issuer,
    Optional<String> subject,
    Optional<String> sid,
    String jwtId) {

  public BackChannelLogoutToken {
    Objects.requireNonNull(issuer, "issuer");
    Objects.requireNonNull(subject, "subject");
    Objects.requireNonNull(sid, "sid");
    Objects.requireNonNull(jwtId, "jwtId");
    if (subject.isEmpty() && sid.isEmpty()) {
      throw new IllegalArgumentException("a logout token must carry sub and/or sid");
    }
  }
}
