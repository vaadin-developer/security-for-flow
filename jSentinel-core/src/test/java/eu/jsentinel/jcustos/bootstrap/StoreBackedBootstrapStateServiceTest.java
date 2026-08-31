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
package eu.jsentinel.jcustos.bootstrap;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("StoreBackedBootstrapStateService")
class StoreBackedBootstrapStateServiceTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
  private static final Instant T1 = Instant.parse("2026-06-01T00:00:00Z");

  private static Clock fixed(Instant at) {
    return Clock.fixed(at, ZoneOffset.UTC);
  }

  @Test
  @DisplayName("fresh store → bootstrapRequired=true, hasAdministrator=false, state.required")
  void freshStore() {
    InMemoryBootstrapStateStore store = new InMemoryBootstrapStateStore();
    StoreBackedBootstrapStateService service = new StoreBackedBootstrapStateService(
        store, TenantId.DEFAULT, BootstrapMode.TRANSIENT_CONSOLE, fixed(T0));

    assertTrue(service.bootstrapRequired());
    assertFalse(service.hasAdministrator());
    assertFalse(service.state().adminCreated());
    assertEquals(Optional.empty(), service.state().adminCreatedAt());
  }

  @Test
  @DisplayName("markCompleted flips state, persists creation instant, is idempotent")
  void markCompletedIdempotent() {
    InMemoryBootstrapStateStore store = new InMemoryBootstrapStateStore();
    StoreBackedBootstrapStateService atT0 = new StoreBackedBootstrapStateService(
        store, TenantId.DEFAULT, BootstrapMode.TRANSIENT_CONSOLE, fixed(T0));

    BootstrapState first = atT0.markCompleted();
    assertTrue(first.adminCreated());
    assertEquals(Optional.of(T0), first.adminCreatedAt());
    assertFalse(atT0.bootstrapRequired());
    assertTrue(atT0.hasAdministrator());

    // Second call with a later clock must NOT overwrite the first completion instant
    StoreBackedBootstrapStateService atT1 = new StoreBackedBootstrapStateService(
        store, TenantId.DEFAULT, BootstrapMode.TRANSIENT_CONSOLE, fixed(T1));
    BootstrapState second = atT1.markCompleted();
    assertEquals(Optional.of(T0), second.adminCreatedAt(),
        "markCompleted must preserve the original completion instant");
  }

  @Test
  @DisplayName("BootstrapMode.DISABLED forces bootstrapRequired=false regardless of state")
  void disabledModeAlwaysSkipsBootstrap() {
    InMemoryBootstrapStateStore store = new InMemoryBootstrapStateStore();
    StoreBackedBootstrapStateService service = new StoreBackedBootstrapStateService(
        store, TenantId.DEFAULT, BootstrapMode.DISABLED, fixed(T0));

    assertFalse(service.bootstrapRequired());
    assertFalse(service.hasAdministrator());

    // hasAdministrator stays correct even when mode==DISABLED
    new StoreBackedBootstrapStateService(store, TenantId.DEFAULT, BootstrapMode.TRANSIENT_CONSOLE, fixed(T0))
        .markCompleted();
    assertFalse(service.bootstrapRequired());
    assertTrue(service.hasAdministrator(),
        "hasAdministrator reads the persisted state — DISABLED only shortcuts bootstrapRequired");
  }

  @Test
  @DisplayName("reset clears the persisted completion for the bound tenant")
  void resetClears() {
    InMemoryBootstrapStateStore store = new InMemoryBootstrapStateStore();
    StoreBackedBootstrapStateService service = new StoreBackedBootstrapStateService(
        store, TenantId.DEFAULT, BootstrapMode.TRANSIENT_CONSOLE, fixed(T0));
    service.markCompleted();
    assertTrue(service.hasAdministrator());

    assertTrue(service.reset());
    assertFalse(service.hasAdministrator());
    assertTrue(service.bootstrapRequired());
    assertFalse(service.reset(), "second reset is a no-op");
  }

  @Test
  @DisplayName("service is tenant-scoped — completing acme does not complete default")
  void tenantScoped() {
    InMemoryBootstrapStateStore store = new InMemoryBootstrapStateStore();
    TenantId acme = new TenantId("acme");
    StoreBackedBootstrapStateService defaultSvc = new StoreBackedBootstrapStateService(
        store, TenantId.DEFAULT, BootstrapMode.TRANSIENT_CONSOLE, fixed(T0));
    StoreBackedBootstrapStateService acmeSvc = new StoreBackedBootstrapStateService(
        store, acme, BootstrapMode.TRANSIENT_CONSOLE, fixed(T0));

    acmeSvc.markCompleted();

    assertTrue(acmeSvc.hasAdministrator());
    assertFalse(defaultSvc.hasAdministrator());
    assertTrue(defaultSvc.bootstrapRequired());
  }

  @Test
  @DisplayName("default constructor uses TenantId.DEFAULT, BootstrapMode.ENABLED, system clock")
  void defaultConstructorMetadata() {
    InMemoryBootstrapStateStore store = new InMemoryBootstrapStateStore();
    StoreBackedBootstrapStateService service = new StoreBackedBootstrapStateService(store);
    assertEquals(TenantId.DEFAULT, service.tenant());
    assertEquals(BootstrapMode.TRANSIENT_CONSOLE, service.mode());
  }

  @Test
  @DisplayName("null arguments are rejected")
  void rejectNulls() {
    InMemoryBootstrapStateStore store = new InMemoryBootstrapStateStore();
    assertThrows(NullPointerException.class,
        () -> new StoreBackedBootstrapStateService(null));
    assertThrows(NullPointerException.class,
        () -> new StoreBackedBootstrapStateService(store, TenantId.DEFAULT, null, fixed(T0)));
    assertThrows(NullPointerException.class,
        () -> new StoreBackedBootstrapStateService(store, TenantId.DEFAULT, BootstrapMode.TRANSIENT_CONSOLE, null));
  }
}
