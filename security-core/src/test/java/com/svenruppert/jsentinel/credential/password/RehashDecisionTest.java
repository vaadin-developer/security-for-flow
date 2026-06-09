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


import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

class RehashDecisionTest {

  @Test
  @DisplayName("NotRequired is shareable through INSTANCE")
  void notRequiredHasSingleton() {
    assertNotNull(RehashDecision.NotRequired.INSTANCE);
    assertSame(RehashDecision.NotRequired.INSTANCE,
        RehashDecision.NotRequired.INSTANCE);
  }

  @Test
  @DisplayName("Required carries reason and target policy version")
  void requiredCarriesReason() {
    RehashDecision decision = new RehashDecision.Required(
        RehashReason.POLICY_VERSION_OUTDATED, 2);

    RehashDecision.Required r = assertInstanceOf(
        RehashDecision.Required.class, decision);
    assertEquals(RehashReason.POLICY_VERSION_OUTDATED, r.reason());
    assertEquals(2, r.targetPolicyVersion());
  }

  @Test
  @DisplayName("Required rejects null reason and non-positive policy version")
  void requiredRejectsInvalid() {
    assertThrows(NullPointerException.class,
        () -> new RehashDecision.Required(null, 1));
    assertThrows(IllegalArgumentException.class,
        () -> new RehashDecision.Required(RehashReason.ALGORITHM_DEPRECATED, 0));
  }
}
