package eu.jsentinel.jcustos.events.producer;

/*-
 * #%L
 * jSentinel Events — Security Event Bus core
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2026 jSentinel by Sven Ruppert
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
import eu.jsentinel.jcustos.events.api.EventProducerId;
import eu.jsentinel.jcustos.events.api.EventType;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("AllowListProducerPolicy")
class AllowListProducerPolicyTest {

  private static final EventProducerId REST = EventProducerId.of("rest-service-primary");
  private static final EventProducerId VAADIN = EventProducerId.of("vaadin-client");
  private static final EventType LOGIN = EventType.of("LoginSucceeded");
  private static final EventType ROLE = EventType.of("RoleAssigned");
  private static final EventType SESSION_REVOKED = EventType.of("SessionRevoked");
  private static final TenantId ACME = TenantId.of("acme");

  @Test
  @DisplayName("an allowed producer may publish an allowed type for any tenant")
  void allowedProducerAllowedType() {
    JSentinelEventProducerPolicy policy = AllowListProducerPolicy.builder()
        .allow(REST, LOGIN)
        .allow(REST, ROLE)
        .build();
    assertTrue(policy.mayPublish(REST, LOGIN, TenantId.DEFAULT));
    assertTrue(policy.mayPublish(REST, ROLE, ACME));
  }

  @Test
  @DisplayName("an allowed producer is not implicitly allowed every type (default deny)")
  void notAllTypesAllowed() {
    JSentinelEventProducerPolicy policy = AllowListProducerPolicy.builder()
        .allow(REST, LOGIN)
        .build();
    assertFalse(policy.mayPublish(REST, SESSION_REVOKED, TenantId.DEFAULT));
  }

  @Test
  @DisplayName("an unlisted producer is rejected")
  void unlistedProducerRejected() {
    JSentinelEventProducerPolicy policy = AllowListProducerPolicy.builder()
        .allow(REST, SESSION_REVOKED)
        .build();
    assertFalse(policy.mayPublish(VAADIN, SESSION_REVOKED, TenantId.DEFAULT));
  }

  @Test
  @DisplayName("tenant-specific grants are honoured only for that tenant")
  void tenantSpecificGrant() {
    JSentinelEventProducerPolicy policy = AllowListProducerPolicy.builder()
        .allowForTenant(VAADIN, LOGIN, ACME)
        .build();
    assertTrue(policy.mayPublish(VAADIN, LOGIN, ACME));
    assertFalse(policy.mayPublish(VAADIN, LOGIN, TenantId.DEFAULT));
  }
}
