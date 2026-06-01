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

package com.svenruppert.vaadin.security.credential;


import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

class CredentialTypeTest {

  @Test
  @DisplayName("Phase 1a supports exactly PASSWORD as credential type")
  void phase1aSupportsOnlyPassword() {
    assertArrayEquals(
        new CredentialType[]{CredentialType.PASSWORD},
        CredentialType.values()
    );
  }

  @Test
  @DisplayName("CredentialType.PASSWORD is the canonical default")
  void passwordIsCanonicalDefault() {
    assertEquals("PASSWORD", CredentialType.PASSWORD.name());
  }
}
