/*-
 * #%L
 * Security Core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or – as soon they will be
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

package com.svenruppert.vaadin.security.credential.password;


import com.svenruppert.vaadin.security.credential.CredentialType;
import com.svenruppert.vaadin.security.credential.InternalAuditEventType;
import com.svenruppert.vaadin.security.credential.PublicFailureType;

import java.util.Objects;
import java.util.Optional;

/**
 * Structured outcome of a credential verification.
 *
 * <p>Replaces the experimental boolean-only verification API. The two
 * permitted variants intentionally carry different vocabularies:</p>
 *
 * <ul>
 *   <li>{@link Verified} exposes the metadata required for transparent
 *       rehash (in particular the {@code originalEncodedHash} so that
 *       persistent stores can perform a compare-and-swap update);</li>
 *   <li>{@link Failed} separates the
 *       {@linkplain PublicFailureType public-facing classification}
 *       from the
 *       {@linkplain InternalAuditEventType internal audit classification},
 *       so that perimeter responses stay generic while audit sinks can
 *       differentiate.</li>
 * </ul>
 */
public sealed interface CredentialVerificationResult
    permits CredentialVerificationResult.Verified,
            CredentialVerificationResult.Failed {

  /**
   * Successful verification. Carries every piece of metadata the caller
   * needs to decide whether to perform a transparent rehash and to do
   * so atomically against the credential store.
   *
   * @param originalEncodedHash the encoded envelope that was just
   *                            verified; required as the
   *                            compare-and-swap witness for any rehash
   * @param credentialType      credential discriminator
   * @param algorithm           algorithm of the verified envelope
   * @param providerId          provider identifier of the verified envelope
   * @param formatVersion       envelope format version of the verified envelope
   * @param policyVersion       policy version recorded in the envelope
   * @param pepperKeyId         pepper key id recorded in the envelope, if any
   */
  record Verified(
      String originalEncodedHash,
      CredentialType credentialType,
      String algorithm,
      String providerId,
      int formatVersion,
      int policyVersion,
      Optional<String> pepperKeyId
  ) implements CredentialVerificationResult {

    public Verified {
      Objects.requireNonNull(originalEncodedHash, "originalEncodedHash");
      if (originalEncodedHash.isBlank()) {
        throw new IllegalArgumentException("originalEncodedHash must not be blank");
      }
      Objects.requireNonNull(credentialType, "credentialType");
      Objects.requireNonNull(algorithm, "algorithm");
      Objects.requireNonNull(providerId, "providerId");
      if (formatVersion < 1) {
        throw new IllegalArgumentException("formatVersion must be >= 1");
      }
      if (policyVersion < 1) {
        throw new IllegalArgumentException("policyVersion must be >= 1");
      }
      Objects.requireNonNull(pepperKeyId, "pepperKeyId");
    }

    @Override
    public String toString() {
      return "Verified["
          + "credentialType=" + credentialType
          + ", algorithm=" + algorithm
          + ", providerId=" + providerId
          + ", formatVersion=" + formatVersion
          + ", policyVersion=" + policyVersion
          + ", pepperKeyId=" + (pepperKeyId.isPresent() ? "<present>" : "<absent>")
          + ", originalEncodedHash=<redacted>"
          + "]";
    }
  }

  /**
   * Verification did not succeed. Reasons range from a genuine credential
   * mismatch through structural envelope problems to provider-level
   * unavailability. The two classification fields are independent on
   * purpose: every public reaction must be derivable from
   * {@link #publicFailureType()} alone.
   *
   * @param publicFailureType     classification suitable for UI/API surfaces
   * @param internalAuditEventType internal classification for audit sinks
   */
  record Failed(
      PublicFailureType publicFailureType,
      InternalAuditEventType internalAuditEventType
  ) implements CredentialVerificationResult {

    public Failed {
      Objects.requireNonNull(publicFailureType, "publicFailureType");
      Objects.requireNonNull(internalAuditEventType, "internalAuditEventType");
    }
  }
}
