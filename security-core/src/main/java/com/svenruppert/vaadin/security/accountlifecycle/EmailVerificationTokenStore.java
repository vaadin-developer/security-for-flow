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
package com.svenruppert.vaadin.security.accountlifecycle;

import com.svenruppert.vaadin.security.authorization.api.ExperimentalSecurityApi;
import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;

import java.time.Instant;
import java.util.Optional;

/**
 * Persistent store for {@link EmailVerificationTokenRecord}s —
 * backs the planned email-verification workflow (V00.70 Phase 7).
 * <p>
 * Same lifecycle as
 * {@link PasswordResetTokenStore}: hash-only, single-use, consumed
 * records remain visible to {@link #findByHash(String)} so callers
 * can distinguish "already consumed" from "never existed".
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalSecurityApi
public interface EmailVerificationTokenStore {

  /**
   * Looks up a token record by its hash.
   *
   * @param tokenHash token hash; must not be {@code null} or blank
   * @return the record, if present (consumed or otherwise)
   */
  Optional<EmailVerificationTokenRecord> findByHash(String tokenHash);

  /**
   * Persists or replaces the supplied token record (keyed on
   * {@link EmailVerificationTokenRecord#tokenHash()}).
   *
   * @param record record to persist; must not be {@code null}
   */
  void save(EmailVerificationTokenRecord record);

  /**
   * Marks the record for {@code tokenHash} consumed. No-op when
   * already consumed.
   *
   * @param tokenHash token hash; must not be {@code null} or blank
   * @param at        consumption instant; must not be {@code null}
   * @return {@code true} if a pending record was just marked
   *         consumed; {@code false} otherwise
   */
  boolean markConsumed(String tokenHash, Instant at);

  /**
   * Drops every token issued to {@code subjectId} within
   * {@code tenant}.
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
