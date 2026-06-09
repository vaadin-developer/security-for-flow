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
package com.svenruppert.jsentinel.audit;

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("StoreBackedJSentinelAuditService")
class StoreBackedJSentinelAuditServiceTest {

  private static AuditEvent loginSucceededAt(Instant t, String user) {
    return new LoginSucceeded(t, user, "127.0.0.1", "sid-" + user);
  }

  @Test
  @DisplayName("publish appends to the backing store; query returns the events")
  void publishAndQueryRoundtrip() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    StoreBackedJSentinelAuditService service = new StoreBackedJSentinelAuditService(store);

    AuditEvent event = loginSucceededAt(Instant.now(), "alice");
    service.publish(event);

    List<AuditEvent> all = service.query(AuditQuery.all());
    assertEquals(List.of(event), all);
  }

  @Test
  @DisplayName("publish on a null event is a silent no-op (audit failure must not break the flow)")
  void publishNullSilent() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    StoreBackedJSentinelAuditService service = new StoreBackedJSentinelAuditService(store);
    service.publish(null);
    assertTrue(service.query(AuditQuery.all()).isEmpty());
  }

  @Test
  @DisplayName("publish swallows store failures — audit must never break the security flow")
  void publishSwallowsStoreFailures() {
    AuditEventStore failingStore = new AuditEventStore() {
      @Override public AuditEnvelope append(TenantId tenant, AuditEvent event) {
        throw new RuntimeException("simulated store failure");
      }
      @Override public List<AuditEnvelope> query(TenantId tenant, AuditQuery query) {
        return List.of();
      }
      @Override public int purgeOlderThan(Instant cutoff) { return 0; }
    };
    StoreBackedJSentinelAuditService service =
        new StoreBackedJSentinelAuditService(failingStore);
    service.publish(loginSucceededAt(Instant.now(), "alice"));
    // no exception escaped — that is the contract
  }

  @Test
  @DisplayName("query passes the tenant through to the store")
  void queryIsTenantScoped() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    TenantId acme = new TenantId("acme");
    StoreBackedJSentinelAuditService defaultService = new StoreBackedJSentinelAuditService(store);
    StoreBackedJSentinelAuditService acmeService =
        new StoreBackedJSentinelAuditService(store, acme);

    defaultService.publish(loginSucceededAt(Instant.now(), "alice"));
    acmeService.publish(loginSucceededAt(Instant.now(), "bob"));

    assertEquals(1, defaultService.query(AuditQuery.all()).size());
    assertEquals(1, acmeService.query(AuditQuery.all()).size());
    assertEquals("bob",
        ((LoginSucceeded) acmeService.query(AuditQuery.all()).getFirst()).username());
  }

  @Test
  @DisplayName("two-arg constructor null tenant normalises to DEFAULT")
  void nullTenantBecomesDefault() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    StoreBackedJSentinelAuditService service =
        new StoreBackedJSentinelAuditService(store, null);
    assertSame(TenantId.DEFAULT, service.tenant());
  }

  @Test
  @DisplayName("query returns an immutable result")
  void queryReturnsImmutable() {
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    StoreBackedJSentinelAuditService service = new StoreBackedJSentinelAuditService(store);
    service.publish(loginSucceededAt(Instant.now(), "alice"));

    List<AuditEvent> result = service.query(AuditQuery.all());
    assertThrows(UnsupportedOperationException.class,
        () -> result.add(loginSucceededAt(Instant.now(), "intruder")));
  }

  @Test
  @DisplayName("null store / query is rejected")
  void rejectNulls() {
    assertThrows(NullPointerException.class,
        () -> new StoreBackedJSentinelAuditService(null));
    InMemoryAuditEventStore store = new InMemoryAuditEventStore();
    StoreBackedJSentinelAuditService service = new StoreBackedJSentinelAuditService(store);
    assertThrows(NullPointerException.class, () -> service.query(null));
  }
}
