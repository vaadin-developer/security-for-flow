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
package eu.jsentinel.jcustos.credential.reset;

import eu.jsentinel.jcustos.credential.token.TokenDigestRecord;

import java.time.Instant;
import java.util.Objects;

/**
 * Persisted password-reset token. Holds the selector, the digest of the
 * verifier (never the verifier itself), the owner's username, the
 * lifecycle status and the timestamps that drive single-use and expiry.
 *
 * <p>The {@code version} field is an optimistic-lock counter — bumped
 * on every status transition so the store can CAS without losing
 * concurrent updates (CWE-362).</p>
 */
public record ResetTokenRecord(
    TokenDigestRecord digest,
    String username,
    Instant issuedAt,
    Instant expiresAt,
    ResetTokenStatus status,
    long version
) {

  public ResetTokenRecord {
    Objects.requireNonNull(digest, "digest");
    Objects.requireNonNull(username, "username");
    if (username.isBlank()) {
      throw new IllegalArgumentException("username must not be blank");
    }
    Objects.requireNonNull(issuedAt, "issuedAt");
    Objects.requireNonNull(expiresAt, "expiresAt");
    if (!expiresAt.isAfter(issuedAt)) {
      throw new IllegalArgumentException("expiresAt must be after issuedAt");
    }
    Objects.requireNonNull(status, "status");
    if (version < 1L) {
      throw new IllegalArgumentException("version must be >= 1");
    }
  }

  public String selector() {
    return digest.selector();
  }

  public boolean isExpired(Instant now) {
    return !now.isBefore(expiresAt);
  }

  public ResetTokenRecord withStatus(ResetTokenStatus newStatus) {
    return new ResetTokenRecord(digest, username, issuedAt, expiresAt,
        newStatus, version + 1);
  }
}
