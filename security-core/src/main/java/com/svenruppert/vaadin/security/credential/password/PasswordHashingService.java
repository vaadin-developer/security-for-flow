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
package com.svenruppert.vaadin.security.credential.password;

import com.svenruppert.vaadin.security.credential.secret.SecretValue;

import java.util.Arrays;

/**
 * Front-door facade for the Phase-1a password hashing and verification
 * pipeline.
 *
 * <p>The pipeline order is fixed:</p>
 *
 * <pre>{@code
 *   parse -> validate -> resolveProvider -> resolvePepper
 *         -> verify -> rehashDecision
 * }</pre>
 *
 * <p>{@link #verify(char[], String)} returns only
 * {@link CredentialVerificationResult}; the boolean shape of the
 * experimental API is intentionally gone (see CWE-287, CWE-203).</p>
 *
 * <p>{@link #needsRehash(String)} is callable after a successful verify
 * (or independently) to drive transparent upgrades against a
 * compare-and-swap credential store.</p>
 */
public interface PasswordHashingService {

  /**
   * Produces a fresh hash for the given password under the active
   * policy.
   *
   * @param password caller-owned character buffer; the implementation
   *                 must not modify or zero it
   */
  PasswordHashResult hash(char[] password);

  /**
   * Runs the verification pipeline on the supplied envelope.
   */
  CredentialVerificationResult verify(char[] password, String encodedHash);

  /**
   * Reports whether the supplied envelope should be rehashed under the
   * active policy.
   */
  RehashDecision needsRehash(String encodedHash);

  /**
   * Convenience entry point for callers that already know there is no
   * stored envelope to verify against (typically &quot;unknown user&quot;
   * paths). The implementation still performs a comparable KDF call so
   * the response is not distinguishable from a real verification
   * (CWE-203, CWE-208).
   */
  CredentialVerificationResult verifyAgainstNothing(char[] password);

  /**
   * SecretValue overload for {@link #hash(char[])}. The borrowed
   * {@code char[]} copy returned by {@link SecretValue#asChars()} is
   * zeroed in a {@code finally} block (CWE-226).
   */
  default PasswordHashResult hash(SecretValue password) {
    char[] chars = password.asChars();
    try {
      return hash(chars);
    } finally {
      Arrays.fill(chars, '\0');
    }
  }

  /**
   * SecretValue overload for {@link #verify(char[], String)}.
   */
  default CredentialVerificationResult verify(
      SecretValue password, String encodedHash) {
    char[] chars = password.asChars();
    try {
      return verify(chars, encodedHash);
    } finally {
      Arrays.fill(chars, '\0');
    }
  }

  /**
   * SecretValue overload for {@link #verifyAgainstNothing(char[])}.
   */
  default CredentialVerificationResult verifyAgainstNothing(SecretValue password) {
    char[] chars = password.asChars();
    try {
      return verifyAgainstNothing(chars);
    } finally {
      Arrays.fill(chars, '\0');
    }
  }
}
