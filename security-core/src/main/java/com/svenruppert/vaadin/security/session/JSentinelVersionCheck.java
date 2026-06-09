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

import com.svenruppert.vaadin.security.authorization.api.ExperimentalJSentinelApi;

import static java.util.Objects.requireNonNull;

/**
 * Adapter-neutral security-version drift detector.
 * <p>
 * Wraps a {@link JSentinelVersionStore} and exposes a single
 * {@link #check(JSentinelVersionKey, JSentinelVersion) check} method
 * that compares a session's
 * {@link SessionRecord#securityVersionAtLogin() captured version}
 * against the subject's <em>current</em> version. Any inequality —
 * including a snapshot that is <em>ahead</em> of the current value
 * (legitimately produced by
 * {@link JSentinelVersionStore#reset(JSentinelVersionKey)}) — is
 * reported as {@link JSentinelVersionStatus.Drifted}; callers must
 * treat drift as "session no longer authoritative" regardless of
 * direction.
 *
 * <p>Stateless apart from the injected store; safe to share between
 * adapters and threads.
 */
@ExperimentalJSentinelApi
public final class JSentinelVersionCheck {

  private final JSentinelVersionStore store;

  /**
   * @param store backing version store; non-null
   */
  public JSentinelVersionCheck(JSentinelVersionStore store) {
    this.store = requireNonNull(store, "store must not be null");
  }

  /**
   * Compares {@code snapshot} against {@code store.current(key)}.
   *
   * @param key      tenant + subject; non-null
   * @param snapshot version captured when the session was opened;
   *                 non-null
   * @return {@link JSentinelVersionStatus.Current} when both values
   *         match, otherwise
   *         {@link JSentinelVersionStatus.Drifted}
   */
  public JSentinelVersionStatus check(JSentinelVersionKey key,
                                     JSentinelVersion snapshot) {
    requireNonNull(key, "key must not be null");
    requireNonNull(snapshot, "snapshot must not be null");
    JSentinelVersion current = store.current(key);
    if (snapshot.equals(current)) {
      return new JSentinelVersionStatus.Current(current);
    }
    return new JSentinelVersionStatus.Drifted(snapshot, current);
  }

  /**
   * Convenience wrapper around
   * {@link #check(JSentinelVersionKey, JSentinelVersion)} that pulls
   * the snapshot straight from a {@link SessionRecord}.
   *
   * @param session session to validate; non-null
   * @return drift status
   */
  public JSentinelVersionStatus check(SessionRecord session) {
    requireNonNull(session, "session must not be null");
    return check(
        new JSentinelVersionKey(session.tenant(), session.subjectId()),
        session.securityVersionAtLogin());
  }
}
