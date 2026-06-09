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
import java.util.Objects;

/**
 * Persisted credential row, returned by {@link CredentialStore} reads
 * and used as the compare-and-swap witness on writes.
 *
 * <p>The {@code version} field is a monotonically increasing
 * optimistic-lock counter: every successful update returns a new record
 * with {@code version + 1}. CAS callers normally hand back the
 * {@code encodedHash} as the witness, but the version field is exposed
 * for adapters that prefer numeric optimistic-lock comparisons.</p>
 *
 * <p>{@link #toString()} never exposes {@link #encodedHash()} (CWE-522 /
 * CWE-209).</p>
 *
 * @param username    case-sensitive identifier; never {@code null} or blank
 * @param encodedHash full Phase-1a envelope as stored
 * @param status      current lifecycle status
 * @param version     optimistic-lock counter, starts at 1
 * @param createdAt   when the record was first written
 * @param updatedAt   when the record was last written
 */
public record CredentialRecord(
    String username,
    String encodedHash,
    CredentialStatus status,
    long version,
    Instant createdAt,
    Instant updatedAt
) {

  public CredentialRecord {
    Objects.requireNonNull(username, "username");
    if (username.isBlank()) {
      throw new IllegalArgumentException("username must not be blank");
    }
    Objects.requireNonNull(encodedHash, "encodedHash");
    if (encodedHash.isBlank()) {
      throw new IllegalArgumentException("encodedHash must not be blank");
    }
    Objects.requireNonNull(status, "status");
    if (version < 1L) {
      throw new IllegalArgumentException("version must be >= 1");
    }
    Objects.requireNonNull(createdAt, "createdAt");
    Objects.requireNonNull(updatedAt, "updatedAt");
  }

  /**
   * Convenience: build a fresh record at version 1 with timestamps
   * equal to {@code now}.
   */
  public static CredentialRecord initial(
      String username, String encodedHash,
      CredentialStatus status, Instant now) {
    return new CredentialRecord(username, encodedHash, status, 1L, now, now);
  }

  /**
   * Returns a new record with the supplied hash and timestamp, version
   * bumped by one.
   */
  public CredentialRecord withHash(String newEncodedHash, Instant when) {
    return new CredentialRecord(
        username, newEncodedHash, status, version + 1, createdAt, when);
  }

  /**
   * Returns a new record with the supplied status and timestamp,
   * version bumped by one.
   */
  public CredentialRecord withStatus(CredentialStatus newStatus, Instant when) {
    return new CredentialRecord(
        username, encodedHash, newStatus, version + 1, createdAt, when);
  }

  @Override
  public String toString() {
    return "CredentialRecord["
        + "username=" + username
        + ", status=" + status
        + ", version=" + version
        + ", createdAt=" + createdAt
        + ", updatedAt=" + updatedAt
        + ", encodedHash=<redacted>"
        + "]";
  }
}
