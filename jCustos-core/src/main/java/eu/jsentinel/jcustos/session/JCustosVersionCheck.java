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
 * Adapter-neutral security-version drift detector.
 * <p>
 * Wraps a {@link JCustosVersionStore} and exposes a single
 * {@link #check(JCustosVersionKey, JCustosVersion) check} method
 * that compares a session's
 * {@link SessionRecord#securityVersionAtLogin() captured version}
 * against the subject's <em>current</em> version. Any inequality —
 * including a snapshot that is <em>ahead</em> of the current value
 * (legitimately produced by
 * {@link JCustosVersionStore#reset(JCustosVersionKey)}) — is
 * reported as {@link JCustosVersionStatus.Drifted}; callers must
 * treat drift as "session no longer authoritative" regardless of
 * direction.
 *
 * <p>Stateless apart from the injected store; safe to share between
 * adapters and threads.
 */
@ExperimentalJCustosApi
public final class JCustosVersionCheck {

  private final JCustosVersionStore store;

  /**
   * @param store backing version store; non-null
   */
  public JCustosVersionCheck(JCustosVersionStore store) {
    this.store = requireNonNull(store, "store must not be null");
  }

  /**
   * Compares {@code snapshot} against {@code store.current(key)}.
   *
   * @param key      tenant + subject; non-null
   * @param snapshot version captured when the session was opened;
   *                 non-null
   * @return {@link JCustosVersionStatus.Current} when both values
   *         match, otherwise
   *         {@link JCustosVersionStatus.Drifted}
   */
  public JCustosVersionStatus check(JCustosVersionKey key,
                                     JCustosVersion snapshot) {
    requireNonNull(key, "key must not be null");
    requireNonNull(snapshot, "snapshot must not be null");
    JCustosVersion current = store.current(key);
    if (snapshot.equals(current)) {
      return new JCustosVersionStatus.Current(current);
    }
    return new JCustosVersionStatus.Drifted(snapshot, current);
  }

  /**
   * Convenience wrapper around
   * {@link #check(JCustosVersionKey, JCustosVersion)} that pulls
   * the snapshot straight from a {@link SessionRecord}.
   *
   * @param session session to validate; non-null
   * @return drift status
   */
  public JCustosVersionStatus check(SessionRecord session) {
    requireNonNull(session, "session must not be null");
    return check(
        new JCustosVersionKey(session.tenant(), session.subjectId()),
        session.securityVersionAtLogin());
  }
}
