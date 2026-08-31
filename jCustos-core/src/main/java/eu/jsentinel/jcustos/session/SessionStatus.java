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
package eu.jsentinel.jcustos.session;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;

/**
 * Lifecycle state of a {@code SessionRecord}.
 * <p>
 * Sessions move through this enum in the following typical
 * progression:
 * <pre>
 *  ACTIVE  --(idle / absolute timeout)--&gt;  EXPIRED
 *  ACTIVE  --(logout / admin revoke)----&gt;  REVOKED
 * </pre>
 * Both terminal states are <em>not</em> deleted from the store
 * immediately; they are kept around until a retention window passes
 * so audit queries can still see them.
 *
 * <p>Adapters consult {@link #isActive()} to decide whether a session
 * is admissible for a request. Terminal states never become active
 * again — re-authentication produces a new {@code SessionRecord} with
 * a fresh {@code SessionId}.
 */
@ExperimentalJCustosApi
public enum SessionStatus {

  /** Session is open and admissible. */
  ACTIVE,

  /** Session was terminated by an idle or absolute timeout. */
  EXPIRED,

  /** Session was terminated explicitly by logout or an admin revoke. */
  REVOKED;

  /**
   * Returns {@code true} only for {@link #ACTIVE}.
   *
   * @return {@code true} if the session is admissible
   */
  public boolean isActive() {
    return this == ACTIVE;
  }
}
