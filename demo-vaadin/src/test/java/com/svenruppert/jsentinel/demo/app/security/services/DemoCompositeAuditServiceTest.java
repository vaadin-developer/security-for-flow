/**
 * Copyright © 2017 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 */
package com.svenruppert.jsentinel.demo.app.security.services;

import com.svenruppert.jsentinel.audit.AuditEvent;
import com.svenruppert.jsentinel.audit.AuditEventStore;
import com.svenruppert.jsentinel.audit.AuditQuery;
import com.svenruppert.jsentinel.audit.InMemoryAuditEventStore;
import com.svenruppert.jsentinel.audit.LoginSucceeded;
import com.svenruppert.jsentinel.audit.JSentinelAuditService;
import com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("DemoCompositeAuditService — V00.70 store-backed audit SPI")
class DemoCompositeAuditServiceTest {

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
  }

  @Test
  @DisplayName("SPI resolves the demo composite service (not the framework default)")
  void spiResolvesDemoService() {
    JSentinelAuditService service = JSentinelServiceResolver.securityAuditService();
    assertInstanceOf(DemoCompositeAuditService.class, service,
        "demo-vaadin must publish DemoCompositeAuditService via META-INF/services");
  }

  @Test
  @DisplayName("publish writes through to the underlying AuditEventStore")
  void publishFlowsThroughStore() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    DemoCompositeAuditService service = new DemoCompositeAuditService(store);

    LoginSucceeded event = new LoginSucceeded(
        Instant.parse("2026-06-07T12:00:00Z"), "alice", "127.0.0.1", null);
    service.publish(event);

    assertEquals(1, store.query(TenantId.DEFAULT, AuditQuery.all()).size(),
        "publish must persist the event in the store");
    assertEquals(event,
        store.query(TenantId.DEFAULT, AuditQuery.all()).get(0).event());
  }

  @Test
  @DisplayName("query reads through the store and honours AuditQuery.ofType")
  void queryHonoursTypeFilter() {
    AuditEventStore store = new InMemoryAuditEventStore();
    DemoCompositeAuditService service = new DemoCompositeAuditService(store);

    service.publish(new LoginSucceeded(
        Instant.parse("2026-06-07T12:00:00Z"), "alice", "127.0.0.1", null));
    service.publish(new LoginSucceeded(
        Instant.parse("2026-06-07T12:00:01Z"), "bob", "127.0.0.1", null));

    List<AuditEvent> all = service.query(AuditQuery.all());
    assertEquals(2, all.size());

    List<AuditEvent> succeeded = service.query(AuditQuery.ofType(LoginSucceeded.class));
    assertEquals(2, succeeded.size(),
        "type filter must match both LoginSucceeded events");
    assertTrue(succeeded.stream().allMatch(LoginSucceeded.class::isInstance));
  }

  @Test
  @DisplayName("null publish is a safe no-op")
  void nullPublishIsNoop() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    DemoCompositeAuditService service = new DemoCompositeAuditService(store);

    service.publish(null);

    assertEquals(0, store.query(TenantId.DEFAULT, AuditQuery.all()).size());
  }
}
