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
package eu.jsentinel.jcustos.authentication;

import eu.jsentinel.jcustos.authorization.api.ExperimentalJCustosApi;
import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.logout.SubjectId;

import java.time.Instant;
import java.util.Optional;

/**
 * Persistent store for {@link RememberMeTokenRecord}s — backs the
 * planned "remember me" / persistent-login flow (V00.70 Phase 7).
 * <p>
 * Tokens are looked up by their <strong>hash</strong>: an auth flow
 * receives the plain token from a client cookie, hashes it, and
 * queries this store. The plain value never enters the store, so
 * an attacker who exfiltrates the store cannot impersonate the
 * subject.
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalJCustosApi
public interface RememberMeTokenStore {

  /**
   * Looks up a token record by its hash.
   *
   * @param tokenHash token hash; must not be {@code null} or blank
   * @return the record, if present
   */
  Optional<RememberMeTokenRecord> findByHash(String tokenHash);

  /**
   * Persists or replaces the supplied token record (keyed on
   * {@link RememberMeTokenRecord#tokenHash()}).
   *
   * @param record record to persist; must not be {@code null}
   */
  void save(RememberMeTokenRecord record);

  /**
   * Removes the record for the given hash.
   *
   * @param tokenHash token hash; must not be {@code null} or blank
   * @return {@code true} if a record was removed,
   *         {@code false} when no such token existed
   */
  boolean deleteByHash(String tokenHash);

  /**
   * Drops every token issued to {@code subjectId} within
   * {@code tenant}. Used by "log out everywhere" flows.
   *
   * @param tenant    tenant scope; must not be {@code null}
   * @param subjectId subject; must not be {@code null}
   * @return number of records removed
   */
  int deleteBySubject(TenantId tenant, SubjectId subjectId);

  /**
   * Drops every token whose {@code expiresAt} is at or before
   * {@code now}. Idempotent.
   *
   * @param now retention boundary; must not be {@code null}
   * @return number of records purged
   */
  int purgeExpired(Instant now);
}
