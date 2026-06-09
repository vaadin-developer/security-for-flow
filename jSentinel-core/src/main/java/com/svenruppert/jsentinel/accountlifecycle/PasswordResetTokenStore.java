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
package com.svenruppert.jsentinel.accountlifecycle;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;

import java.time.Instant;
import java.util.Optional;

/**
 * Persistent store for {@link PasswordResetTokenRecord}s — backs the
 * planned password-reset workflow (V00.70 Phase 7).
 * <p>
 * Tokens are looked up by their <strong>hash</strong>. Single-use:
 * after {@link #markConsumed(String, Instant)} the same hash must
 * never be honoured for a reset again. Implementations must keep
 * consumed records visible to {@link #findByHash(String)} so callers
 * can distinguish "already consumed" from "never existed".
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalJSentinelApi
public interface PasswordResetTokenStore {

  /**
   * Looks up a token record by its hash.
   *
   * @param tokenHash token hash; must not be {@code null} or blank
   * @return the record, if present (consumed or otherwise)
   */
  Optional<PasswordResetTokenRecord> findByHash(String tokenHash);

  /**
   * Persists or replaces the supplied token record (keyed on
   * {@link PasswordResetTokenRecord#tokenHash()}).
   *
   * @param record record to persist; must not be {@code null}
   */
  void save(PasswordResetTokenRecord record);

  /**
   * Marks the record for {@code tokenHash} consumed. No-op when the
   * record is already consumed.
   *
   * @param tokenHash token hash; must not be {@code null} or blank
   * @param at        instant of consumption; must not be {@code null}
   * @return {@code true} if a not-yet-consumed record was marked,
   *         {@code false} when no such record existed or when it was
   *         already consumed
   */
  boolean markConsumed(String tokenHash, Instant at);

  /**
   * Drops every token (consumed or pending) issued to
   * {@code subjectId} within {@code tenant}.
   *
   * @param tenant    tenant scope; must not be {@code null}
   * @param subjectId subject; must not be {@code null}
   * @return number of records removed
   */
  int deleteBySubject(TenantId tenant, SubjectId subjectId);

  /**
   * Drops every record whose {@code expiresAt} is at or before
   * {@code now}.
   *
   * @param now retention boundary; must not be {@code null}
   * @return number of records purged
   */
  int purgeExpired(Instant now);
}
