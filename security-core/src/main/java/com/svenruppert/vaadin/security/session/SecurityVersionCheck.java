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
package com.svenruppert.vaadin.security.session;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;

import static java.util.Objects.requireNonNull;

/**
 * Adapter-neutral security-version drift detector.
 * <p>
 * Wraps a {@link SecurityVersionStore} and exposes a single
 * {@link #check(SecurityVersionKey, SecurityVersion) check} method
 * that compares a session's
 * {@link SessionRecord#securityVersionAtLogin() captured version}
 * against the subject's <em>current</em> version. Any inequality —
 * including a snapshot that is <em>ahead</em> of the current value
 * (legitimately produced by
 * {@link SecurityVersionStore#reset(SecurityVersionKey)}) — is
 * reported as {@link SecurityVersionStatus.Drifted}; callers must
 * treat drift as "session no longer authoritative" regardless of
 * direction.
 *
 * <p>Stateless apart from the injected store; safe to share between
 * adapters and threads.
 */
@ExperimentalSecurityApi
public final class SecurityVersionCheck {

  private final SecurityVersionStore store;

  /**
   * @param store backing version store; non-null
   */
  public SecurityVersionCheck(SecurityVersionStore store) {
    this.store = requireNonNull(store, "store must not be null");
  }

  /**
   * Compares {@code snapshot} against {@code store.current(key)}.
   *
   * @param key      tenant + subject; non-null
   * @param snapshot version captured when the session was opened;
   *                 non-null
   * @return {@link SecurityVersionStatus.Current} when both values
   *         match, otherwise
   *         {@link SecurityVersionStatus.Drifted}
   */
  public SecurityVersionStatus check(SecurityVersionKey key,
                                     SecurityVersion snapshot) {
    requireNonNull(key, "key must not be null");
    requireNonNull(snapshot, "snapshot must not be null");
    SecurityVersion current = store.current(key);
    if (snapshot.equals(current)) {
      return new SecurityVersionStatus.Current(current);
    }
    return new SecurityVersionStatus.Drifted(snapshot, current);
  }

  /**
   * Convenience wrapper around
   * {@link #check(SecurityVersionKey, SecurityVersion)} that pulls
   * the snapshot straight from a {@link SessionRecord}.
   *
   * @param session session to validate; non-null
   * @return drift status
   */
  public SecurityVersionStatus check(SessionRecord session) {
    requireNonNull(session, "session must not be null");
    return check(
        new SecurityVersionKey(session.tenant(), session.subjectId()),
        session.securityVersionAtLogin());
  }
}
