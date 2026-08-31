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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.oidc.api.SessionRegistry;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Handles an OIDC Front-Channel Logout 1.0 request (V00.79): the OP renders the RP's
 * {@code frontchannel_logout_uri} in an iframe with {@code iss} + {@code sid} query
 * parameters. The RP confirms {@code iss} equals its trusted issuer (an attacker cannot
 * log a user out via a forged issuer) and terminates the session for {@code sid}. No
 * token is parsed and no URL is dereferenced — there is nothing to forge but the issuer,
 * which is checked.
 *
 * @since 00.79.10
 */
@ExperimentalJCustosApi
public final class FrontChannelLogoutEndpoint {

  private final String trustedIssuer;
  private final SessionRegistry sessionRegistry;

  public FrontChannelLogoutEndpoint(String trustedIssuer, SessionRegistry sessionRegistry) {
    this.trustedIssuer = Objects.requireNonNull(trustedIssuer, "trustedIssuer");
    this.sessionRegistry = Objects.requireNonNull(sessionRegistry, "sessionRegistry");
  }

  /**
   * Terminates the RP sessions for ({@code iss}, {@code sid}); returns the terminated
   * session ids, or empty when {@code iss} does not match the trusted issuer (request
   * ignored — never an error that reveals session state).
   */
  public Set<String> logout(String iss, Optional<String> sid) {
    Objects.requireNonNull(iss, "iss");
    Objects.requireNonNull(sid, "sid");
    if (!trustedIssuer.equals(iss)) {
      return Set.of();
    }
    return sessionRegistry.terminate(iss, Optional.empty(), sid);
  }
}
