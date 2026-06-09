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
package com.svenruppert.jsentinel.authentication;

import com.svenruppert.jsentinel.authorization.api.ExperimentalJSentinelApi;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.logout.SubjectId;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Persistent store for {@link ApiKeyRecord}s — backs the planned
 * API-key authentication flow (V00.70 Phase 7b).
 * <p>
 * Keys are looked up by their <strong>hash</strong>; the plain value
 * never enters the store. Revoked and expired records remain visible
 * to {@link #findByHash(String)} so the auth flow can distinguish
 * "known but rejected" from "unknown".
 *
 * <p>Implementations must be thread-safe.
 */
@ExperimentalJSentinelApi
public interface ApiKeyStore {

  /**
   * Looks up an API-key record by its hash.
   *
   * @param keyHash key hash; must not be {@code null} or blank
   * @return the record, if present
   */
  Optional<ApiKeyRecord> findByHash(String keyHash);

  /**
   * Persists or replaces the supplied record. Keyed on
   * {@link ApiKeyRecord#keyHash()}.
   *
   * @param record record to persist; must not be {@code null}
   */
  void save(ApiKeyRecord record);

  /**
   * Returns every record (active, revoked, or expired) belonging to
   * {@code subjectId} within {@code tenant}, in insertion order
   * (oldest first). Used by an "manage my API keys" UI.
   *
   * @param tenant    tenant scope; must not be {@code null}
   * @param subjectId subject; must not be {@code null}
   * @return immutable list of records; empty when none exist
   */
  List<ApiKeyRecord> listBySubject(TenantId tenant, SubjectId subjectId);

  /**
   * Updates the {@link ApiKeyRecord#lastUsedAt()} timestamp of the
   * record for {@code keyHash}.
   *
   * @param keyHash key hash; must not be {@code null} or blank
   * @param at      instant of use; must not be {@code null}
   * @return {@code true} if the record existed and was updated,
   *         {@code false} when no such key existed
   */
  boolean markUsed(String keyHash, Instant at);

  /**
   * Marks the record for {@code keyHash} revoked at {@code at}.
   * No-op on an already-revoked record.
   *
   * @param keyHash key hash; must not be {@code null} or blank
   * @param at      instant of revocation; must not be {@code null}
   * @return {@code true} if a not-yet-revoked record was marked,
   *         {@code false} when no such key existed or when it was
   *         already revoked
   */
  boolean revoke(String keyHash, Instant at);

  /**
   * Removes the record for {@code keyHash}.
   *
   * @param keyHash key hash; must not be {@code null} or blank
   * @return {@code true} when a record was removed
   */
  boolean deleteByHash(String keyHash);

  /**
   * Drops every record whose {@link ApiKeyRecord#expiresAt()} is at
   * or before {@code now}.
   *
   * @param now retention boundary; must not be {@code null}
   * @return number of records purged
   */
  int purgeExpired(Instant now);
}
