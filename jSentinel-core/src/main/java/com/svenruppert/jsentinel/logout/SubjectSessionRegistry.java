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
package com.svenruppert.jsentinel.logout;

import java.util.Collection;

/**
 * Tracks active sessions per {@link SubjectId}.
 * <p>
 * The {@code LogoutService} consults the registry to enumerate all
 * sessions for a subject when handling
 * {@link LogoutScope#AllSessionsOfSubject}. Each session is identified
 * by an opaque application-defined string (a token, a Vaadin session id,
 * a Servlet session id) so the registry stays adapter-neutral.
 * <p>
 * Implementations must be thread-safe.
 */
public interface SubjectSessionRegistry {

  /**
   * Records that {@code sessionId} belongs to {@code subjectId}.
   * Idempotent — registering the same pair twice is a no-op.
   *
   * @param subjectId subject the session belongs to
   * @param sessionId opaque session identifier (token, session id, …)
   */
  void register(SubjectId subjectId, String sessionId);

  /**
   * Removes the {@code (subjectId, sessionId)} association if present.
   * No-op for unknown sessions.
   *
   * @param subjectId subject the session belongs to
   * @param sessionId opaque session identifier
   */
  void unregister(SubjectId subjectId, String sessionId);

  /**
   * Returns every session id currently associated with {@code subjectId}.
   * The returned collection is a snapshot; subsequent
   * {@link #register(SubjectId, String) register} /
   * {@link #unregister(SubjectId, String) unregister} calls do not leak
   * into it.
   *
   * @param subjectId subject to query
   * @return snapshot of active session ids, possibly empty
   */
  Collection<String> sessionsOf(SubjectId subjectId);

  /**
   * Forgets every association for {@code subjectId}. Returns the set of
   * removed session ids so the caller can drive downstream cleanup
   * (e.g. revoke tokens, invalidate Vaadin sessions).
   *
   * @param subjectId subject whose sessions to forget
   * @return removed session ids
   */
  Collection<String> clearAll(SubjectId subjectId);
}
