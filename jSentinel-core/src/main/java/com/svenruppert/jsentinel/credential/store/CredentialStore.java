/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package com.svenruppert.jsentinel.credential.store;

import java.time.Instant;
import java.util.Optional;

/**
 * Persistence-neutral credential store.
 *
 * <p>The store is the only place that knows how credentials are
 * persisted — file, RDBMS, key-value store. The security-core uses it
 * exclusively through this interface so the core never gains a
 * production database dependency.</p>
 *
 * <p>Updates are <em>compare-and-swap</em>: the caller supplies a
 * witness (the encoded hash or status it just read) and the store only
 * applies the change if the witness still matches the persisted value
 * (CWE-362 / CWE-367 / CWE-667). Blind overwrites are not supported —
 * callers must re-read, decide and retry.</p>
 */
public interface CredentialStore {

  /**
   * Looks up the credential row for {@code username}. Returns
   * {@link Optional#empty()} when the username is unknown.
   */
  Optional<CredentialRecord> findByUsername(String username);

  /**
   * Atomically replaces the stored hash if it still matches
   * {@code expectedEncodedHash}.
   *
   * @param username             credential identifier
   * @param expectedEncodedHash  witness; usually the {@code encodedHash}
   *                             that {@code findByUsername} just returned
   * @param newEncodedHash       new envelope to persist
   * @param when                 timestamp for {@code updatedAt}; the
   *                             store does not call {@link Instant#now}
   *                             itself so callers can inject a clock
   */
  CredentialUpdateResult updateHashIfCurrent(
      String username,
      String expectedEncodedHash,
      String newEncodedHash,
      Instant when);

  /**
   * Atomically replaces the stored status if it still matches
   * {@code expectedStatus}.
   */
  CredentialUpdateResult updateStatusIfCurrent(
      String username,
      CredentialStatus expectedStatus,
      CredentialStatus newStatus,
      Instant when);
}
