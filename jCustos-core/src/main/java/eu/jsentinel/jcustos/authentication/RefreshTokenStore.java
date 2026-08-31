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
 * Persistent store for {@link RefreshTokenRecord}s — backs the
 * planned rotating-refresh-token flow (V00.70 Phase 7b).
 * <p>
 * Hash-only lookups. Rotation is recorded by calling
 * {@link #markReplaced(String, String, Instant)} on the consumed
 * record after saving its successor. Replayed/already-rotated
 * tokens are detected by inspecting
 * {@link RefreshTokenRecord#replacedByHash()} at validation time;
 * a chain-revoke is the application's responsibility.
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalJCustosApi
public interface RefreshTokenStore {

  /**
   * Looks up a record by its hash.
   *
   * @param tokenHash token hash; must not be {@code null} or blank
   * @return the record, if present
   */
  Optional<RefreshTokenRecord> findByHash(String tokenHash);

  /**
   * Persists or replaces the supplied record. Keyed on
   * {@link RefreshTokenRecord#tokenHash()}.
   *
   * @param record record to persist; must not be {@code null}
   */
  void save(RefreshTokenRecord record);

  /**
   * Links {@code oldHash} as replaced by {@code newHash} at {@code at}.
   * No-op when {@code oldHash} already carries a successor.
   *
   * @param oldHash hash of the consumed token; non-blank
   * @param newHash hash of the successor; non-blank
   * @param at      rotation instant; non-null (recorded as the
   *                consumed record's {@code revokedAt} is left
   *                untouched — replacement is tracked through
   *                {@code replacedByHash} only)
   * @return {@code true} if the link was set on a record that
   *         previously had no successor; {@code false} otherwise
   */
  boolean markReplaced(String oldHash, String newHash, Instant at);

  /**
   * Marks the record for {@code tokenHash} revoked at {@code at}.
   * No-op when the record is already revoked.
   *
   * @param tokenHash token hash; non-blank
   * @param at        revocation instant; non-null
   * @return {@code true} if a not-yet-revoked record was marked
   */
  boolean markRevoked(String tokenHash, Instant at);

  /**
   * Drops every token (active, replaced or revoked) issued to
   * {@code subjectId} within {@code tenant}.
   *
   * @param tenant    tenant scope; non-null
   * @param subjectId subject; non-null
   * @return number of records removed
   */
  int deleteBySubject(TenantId tenant, SubjectId subjectId);

  /**
   * Drops every record whose {@link RefreshTokenRecord#expiresAt()}
   * is at or before {@code now}.
   *
   * @param now retention boundary; non-null
   * @return number of records purged
   */
  int purgeExpired(Instant now);
}
