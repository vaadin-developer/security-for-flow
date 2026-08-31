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

import eu.jsentinel.jcustos.authorization.api.ExperimentalJSentinelApi;

import java.util.Objects;
import java.util.Set;

/**
 * The result of receiving a Back-Channel Logout request (V00.79), sealed. Maps directly
 * to the OIDC Back-Channel Logout 1.0 §2.7 HTTP response: {@code Accepted} → 200,
 * {@code Rejected} → 400. {@code Accepted} carries the RP session ids that were
 * terminated (possibly empty when nothing matched — still a 200, never a leak).
 *
 * @since 00.79.10
 */
@ExperimentalJSentinelApi
public sealed interface BackChannelLogoutOutcome {

  record Accepted(Set<String> terminatedSessionIds) implements BackChannelLogoutOutcome {
    public Accepted {
      terminatedSessionIds = Set.copyOf(Objects.requireNonNull(terminatedSessionIds, "terminatedSessionIds"));
    }
  }

  record Rejected(LogoutTokenValidationError error) implements BackChannelLogoutOutcome {
    public Rejected {
      Objects.requireNonNull(error, "error");
    }
  }
}
