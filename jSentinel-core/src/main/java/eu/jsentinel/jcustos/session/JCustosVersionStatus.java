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

import static java.util.Objects.requireNonNull;

/**
 * Result of a {@link JCustosVersionCheck#check} call against a
 * {@link SessionRecord#securityVersionAtLogin() session snapshot}.
 * <p>
 * Sealed because callers in the Vaadin / REST adapters dispatch on
 * the two outcomes — a session is either current (continue the
 * request) or drifted (refuse the session, force re-login).
 *
 * <p>Adapter-neutral. The Vaadin adapter maps {@link Drifted} to a
 * reroute, the REST adapter maps it to 401 with
 * {@code WWW-Authenticate: SessionStale}.
 */
@ExperimentalJCustosApi
public sealed interface JCustosVersionStatus {

  /**
   * @return the version snapshot the session was opened with
   */
  JCustosVersion snapshot();

  /**
   * @return the subject's current security version
   */
  JCustosVersion current();

  /**
   * @return {@code true} when {@link #snapshot()} equals
   *         {@link #current()}, i.e. the session is still
   *         authoritative
   */
  default boolean isCurrent() {
    return this instanceof Current;
  }

  /**
   * @return {@code true} when {@link #snapshot()} differs from
   *         {@link #current()}, i.e. the session must be re-validated
   */
  default boolean isDrifted() {
    return this instanceof Drifted;
  }

  /**
   * Session is still current — its snapshot matches the subject's
   * stored version.
   *
   * @param at version snapshot, which equals
   *           {@link JCustosVersionCheck} current value
   */
  record Current(JCustosVersion at) implements JCustosVersionStatus {
    /** Validates the component. */
    public Current {
      requireNonNull(at, "at must not be null");
    }

    @Override
    public JCustosVersion snapshot() {
      return at;
    }

    @Override
    public JCustosVersion current() {
      return at;
    }
  }

  /**
   * Session has drifted — its snapshot differs from the subject's
   * stored version. Includes both values so callers (e.g. audit
   * sinks) can record the delta.
   *
   * @param snapshot version captured when the session was opened
   * @param current  subject's current version at check time
   */
  record Drifted(JCustosVersion snapshot, JCustosVersion current) implements JCustosVersionStatus {
    /** Validates the components and asserts they differ. */
    public Drifted {
      requireNonNull(snapshot, "snapshot must not be null");
      requireNonNull(current, "current must not be null");
      if (snapshot.equals(current)) {
        throw new IllegalArgumentException(
            "Drifted requires snapshot != current");
      }
    }
  }
}
