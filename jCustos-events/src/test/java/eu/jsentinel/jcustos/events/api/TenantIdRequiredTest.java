package eu.jsentinel.jcustos.events.api;

/*-
 * #%L
 * jCustos Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jCustos by Sven Ruppert
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

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Dedicated coverage of the cross-cutting invariant "TenantId is mandatory on
 * every envelope" (Konzept §47, §176).
 */
@DisplayName("Envelope — TenantId is mandatory")
class TenantIdRequiredTest {

  @Test
  @DisplayName("null tenantId is rejected by the envelope constructor")
  void nullTenantIdRejectedByRecord() {
    assertThrows(NullPointerException.class,
        () -> EnvelopeFixtures.validBuilder().tenantId(null).build());
  }

  @Test
  @DisplayName("a system-wide event uses TenantId.DEFAULT, never null")
  void systemWideUsesDefaultTenant() {
    SignedJCustosEventEnvelope envelope =
        EnvelopeFixtures.validBuilder().tenantId(TenantId.DEFAULT).build();
    assertEquals(TenantId.DEFAULT, envelope.tenantId());
  }

  @Test
  @DisplayName("TenantId.of rejects blank tenant identifiers")
  void blankTenantRejected() {
    assertThrows(IllegalArgumentException.class, () -> TenantId.of("  "));
  }
}
