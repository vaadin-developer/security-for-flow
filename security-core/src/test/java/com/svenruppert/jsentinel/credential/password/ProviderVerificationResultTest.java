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

package com.svenruppert.jsentinel.credential.password;


import com.svenruppert.jsentinel.credential.InternalAuditEventType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProviderVerificationResultTest {

  @Test
  @DisplayName("Matched is shareable through INSTANCE")
  void matchedHasSingleton() {
    assertSame(ProviderVerificationResult.Matched.INSTANCE,
        ProviderVerificationResult.Matched.INSTANCE);
  }

  @Test
  @DisplayName("NotMatched is shareable through INSTANCE")
  void notMatchedHasSingleton() {
    assertSame(ProviderVerificationResult.NotMatched.INSTANCE,
        ProviderVerificationResult.NotMatched.INSTANCE);
  }

  @Test
  @DisplayName("ProviderError carries internal classification and message")
  void providerErrorCarriesClassification() {
    ProviderVerificationResult result = new ProviderVerificationResult.ProviderError(
        InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR,
        "PBKDF2 service unavailable"
    );
    ProviderVerificationResult.ProviderError err = assertInstanceOf(
        ProviderVerificationResult.ProviderError.class, result);
    assertEquals(
        InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR,
        err.internalAuditEventType()
    );
    assertEquals("PBKDF2 service unavailable", err.message());
  }

  @Test
  @DisplayName("ProviderError rejects null components")
  void providerErrorRejectsNulls() {
    assertThrows(NullPointerException.class,
        () -> new ProviderVerificationResult.ProviderError(
            null, "msg"));
    assertThrows(NullPointerException.class,
        () -> new ProviderVerificationResult.ProviderError(
            InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR, null));
  }
}
