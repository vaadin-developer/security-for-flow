/*-
 * #%L
 * Security Core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.2 or – as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */

package eu.jsentinel.jcustos.credential.password;


import eu.jsentinel.jcustos.credential.CredentialType;
import eu.jsentinel.jcustos.credential.InternalAuditEventType;
import eu.jsentinel.jcustos.credential.PublicFailureType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CredentialVerificationResultTest {

  private static final String ORIGINAL =
      "pwh:v1:PASSWORD:PBKDF2WithHmacSHA256:pbkdf2-jdk:1::i=210000,s=16:zk7q...";

  @Test
  @DisplayName("Verified carries CAS witness and metadata")
  void verifiedCarriesCasWitness() {
    CredentialVerificationResult result = new CredentialVerificationResult.Verified(
        ORIGINAL,
        CredentialType.PASSWORD,
        "PBKDF2WithHmacSHA256",
        "pbkdf2-jdk",
        1,
        1,
        Optional.empty()
    );

    CredentialVerificationResult.Verified v = assertInstanceOf(
        CredentialVerificationResult.Verified.class, result);
    assertEquals(ORIGINAL, v.originalEncodedHash());
    assertEquals(CredentialType.PASSWORD, v.credentialType());
    assertEquals("pbkdf2-jdk", v.providerId());
    assertEquals(1, v.formatVersion());
  }

  @Test
  @DisplayName("Verified.toString never exposes the original encoded hash")
  void verifiedToStringRedacted() {
    CredentialVerificationResult.Verified v = new CredentialVerificationResult.Verified(
        ORIGINAL,
        CredentialType.PASSWORD,
        "PBKDF2WithHmacSHA256",
        "pbkdf2-jdk",
        1,
        1,
        Optional.of("pepper-2026-04")
    );
    String text = v.toString();
    assertFalse(text.contains(ORIGINAL));
    assertFalse(text.contains("pepper-2026-04"));
    assertTrue(text.contains("<redacted>"));
    assertTrue(text.contains("<present>"));
  }

  @Test
  @DisplayName("Failed separates public from internal classification")
  void failedSeparatesClassifications() {
    CredentialVerificationResult result = new CredentialVerificationResult.Failed(
        PublicFailureType.INVALID_CREDENTIALS,
        InternalAuditEventType.VERIFICATION_FAILED_DECODE_ERROR
    );

    CredentialVerificationResult.Failed f = assertInstanceOf(
        CredentialVerificationResult.Failed.class, result);
    assertEquals(PublicFailureType.INVALID_CREDENTIALS, f.publicFailureType());
    assertEquals(
        InternalAuditEventType.VERIFICATION_FAILED_DECODE_ERROR,
        f.internalAuditEventType()
    );
  }

  @Test
  @DisplayName("Both variants reject null components")
  void rejectsNulls() {
    assertThrows(NullPointerException.class,
        () -> new CredentialVerificationResult.Verified(
            null, CredentialType.PASSWORD, "PBKDF2WithHmacSHA256", "pbkdf2-jdk",
            1, 1, Optional.empty()));
    assertThrows(IllegalArgumentException.class,
        () -> new CredentialVerificationResult.Verified(
            " ", CredentialType.PASSWORD, "PBKDF2WithHmacSHA256", "pbkdf2-jdk",
            1, 1, Optional.empty()));
    assertThrows(NullPointerException.class,
        () -> new CredentialVerificationResult.Failed(null,
            InternalAuditEventType.VERIFICATION_FAILED_MISMATCH));
    assertThrows(NullPointerException.class,
        () -> new CredentialVerificationResult.Failed(
            PublicFailureType.INVALID_CREDENTIALS, null));
  }
}
