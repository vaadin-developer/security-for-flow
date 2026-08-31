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
package com.svenruppert.jsentinel.session;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;

import java.util.List;
import java.util.Optional;

/**
 * Store for {@link SessionRecord}s, keyed on {@link SessionId}.
 * <p>
 * Distinct from the existing
 * {@link com.svenruppert.jsentinel.logout.SubjectSessionRegistry}
 * which only maps a subject to its set of <em>active</em> session
 * ids (an index used by multi-session logout). {@code SessionStore}
 * owns the canonical, queryable representation of every session —
 * including expired and revoked ones, until they age out via
 * retention. Since V00.81 the retention (and the lazy
 * ACTIVE→EXPIRED transition) is implemented by wrapping the
 * concrete store in a {@link SweepingSessionStore}.
 *
 * <p>Mutation pattern: load a record, copy-with via the {@code with…}
 * methods on {@link SessionRecord}, save the new value. Stores upsert
 * on {@link #save(SessionRecord)} — there is no separate update call.
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalJSentinelApi
public interface SessionStore {

  /**
   * Persists or replaces the supplied session record. Keyed on
   * {@link SessionRecord#sessionId()}.
   *
   * @param session record to persist; must not be {@code null}
   */
  void save(SessionRecord session);

  /**
   * Looks up the record for a session id.
   *
   * @param sessionId session identifier; must not be {@code null}
   * @return the record, if present
   */
  Optional<SessionRecord> findById(SessionId sessionId);

  /**
   * Returns every record (in any {@link SessionStatus}) belonging to
   * {@code subjectId} within {@code tenant}, in insertion order
   * (oldest first).
   *
   * @param tenant    tenant scope; must not be {@code null}
   * @param subjectId subject; must not be {@code null}
   * @return immutable list of records; empty when none exist
   */
  List<SessionRecord> findBySubject(TenantId tenant, SubjectId subjectId);

  /**
   * Removes the record for {@code sessionId}.
   *
   * @param sessionId session identifier; must not be {@code null}
   * @return {@code true} if a record was removed,
   *         {@code false} when no such session existed
   */
  boolean delete(SessionId sessionId);

  /**
   * Returns every record currently persisted, in insertion order.
   * Used by admin tooling — e.g. the Phase-8a
   * {@code SessionManagementView} — that needs the full session
   * inventory across all subjects.
   * <p>
   * Default returns an empty list so pre-existing implementations
   * keep compiling; concrete stores override.
   *
   * @return immutable list of records, possibly empty; never {@code null}
   */
  default List<SessionRecord> findAll() {
    return List.of();
  }
}
