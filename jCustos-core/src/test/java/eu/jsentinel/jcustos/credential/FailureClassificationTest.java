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

package eu.jsentinel.jcustos.credential;


import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FailureClassificationTest {

  @Test
  @DisplayName("Public and internal failure classifications stay distinct types")
  void publicAndInternalAreDistinct() {
    assertNotEquals(
        PublicFailureType.class,
        InternalAuditEventType.class
    );
  }

  @Test
  @DisplayName("PublicFailureType collapses sensitive distinctions to two values")
  void publicFailureTypeIsCollapsed() {
    EnumSet<PublicFailureType> all = EnumSet.allOf(PublicFailureType.class);
    assertEquals(2, all.size(),
        "growing this enum risks leaking enumeration signals to the perimeter");
    assertTrue(all.contains(PublicFailureType.INVALID_CREDENTIALS));
    assertTrue(all.contains(PublicFailureType.TEMPORARILY_UNAVAILABLE));
  }

  @Test
  @DisplayName("InternalAuditEventType covers every Phase-1a failure path")
  void internalAuditCoversFailurePaths() {
    EnumSet<InternalAuditEventType> all = EnumSet.allOf(InternalAuditEventType.class);
    assertTrue(all.contains(InternalAuditEventType.VERIFICATION_SUCCESS));
    assertTrue(all.contains(InternalAuditEventType.VERIFICATION_FAILED_MISMATCH));
    assertTrue(all.contains(InternalAuditEventType.VERIFICATION_FAILED_DECODE_ERROR));
    assertTrue(all.contains(InternalAuditEventType.VERIFICATION_FAILED_UNSUPPORTED_FORMAT_VERSION));
    assertTrue(all.contains(InternalAuditEventType.VERIFICATION_FAILED_UNSUPPORTED_ALGORITHM));
    assertTrue(all.contains(InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PROVIDER));
    assertTrue(all.contains(InternalAuditEventType.VERIFICATION_FAILED_UNKNOWN_PEPPER_KEY));
    assertTrue(all.contains(InternalAuditEventType.VERIFICATION_FAILED_INVALID_PARAMETERS));
    assertTrue(all.contains(InternalAuditEventType.VERIFICATION_FAILED_PROVIDER_ERROR));
    assertTrue(all.contains(InternalAuditEventType.VERIFICATION_REJECTED_KDF_LIMIT));
    assertTrue(all.contains(InternalAuditEventType.VERIFICATION_DUMMY_PATH));
  }
}
