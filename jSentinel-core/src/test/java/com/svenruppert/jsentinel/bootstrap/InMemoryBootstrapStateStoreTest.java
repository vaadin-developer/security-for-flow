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
package com.svenruppert.jsentinel.bootstrap;

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryBootstrapStateStore + BootstrapState")
class InMemoryBootstrapStateStoreTest {

  private static final TenantId ACME = new TenantId("acme");
  private final InMemoryBootstrapStateStore store = new InMemoryBootstrapStateStore();

  // ── BootstrapState invariants ───────────────────────────────────

  @Nested
  @DisplayName("BootstrapState invariants")
  class StateInvariants {

    @Test
    @DisplayName("required(tenant) builds the not-yet-bootstrapped state")
    void requiredFactory() {
      BootstrapState state = BootstrapState.required(TenantId.DEFAULT);
      assertFalse(state.adminCreated());
      assertTrue(state.adminCreatedAt().isEmpty());
    }

    @Test
    @DisplayName("completed(tenant, at) builds the bootstrapped state")
    void completedFactory() {
      Instant at = Instant.parse("2026-01-01T12:00:00Z");
      BootstrapState state = BootstrapState.completed(TenantId.DEFAULT, at);
      assertTrue(state.adminCreated());
      assertEquals(Optional.of(at), state.adminCreatedAt());
    }

    @Test
    @DisplayName("adminCreated=true without an instant is rejected")
    void createdWithoutInstantRejected() {
      assertThrows(IllegalArgumentException.class,
          () -> new BootstrapState(TenantId.DEFAULT, true, Optional.empty()));
    }

    @Test
    @DisplayName("adminCreated=false with an instant is rejected")
    void notCreatedWithInstantRejected() {
      assertThrows(IllegalArgumentException.class,
          () -> new BootstrapState(TenantId.DEFAULT, false,
              Optional.of(Instant.now())));
    }

    @Test
    @DisplayName("null tenant is normalised to DEFAULT")
    void nullTenantBecomesDefault() {
      BootstrapState state = new BootstrapState(null, false, Optional.empty());
      assertEquals(TenantId.DEFAULT, state.tenant());
    }

    @Test
    @DisplayName("null Optional adminCreatedAt is normalised to empty")
    void nullOptionalBecomesEmpty() {
      BootstrapState state = new BootstrapState(TenantId.DEFAULT, false, null);
      assertTrue(state.adminCreatedAt().isEmpty());
    }

    @Test
    @DisplayName("completed(tenant, null) rejects null instant")
    void completedRejectsNullInstant() {
      assertThrows(NullPointerException.class,
          () -> BootstrapState.completed(TenantId.DEFAULT, null));
    }
  }

  // ── store operations ────────────────────────────────────────────

  @Test
  @DisplayName("find on an unknown tenant returns empty")
  void findUnknownTenantEmpty() {
    assertTrue(store.find(TenantId.DEFAULT).isEmpty());
  }

  @Test
  @DisplayName("save persists state retrievable by tenant")
  void saveAndFind() {
    BootstrapState state = BootstrapState.required(TenantId.DEFAULT);
    store.save(state);
    assertEquals(Optional.of(state), store.find(TenantId.DEFAULT));
  }

  @Test
  @DisplayName("save upserts on the tenant key (transition required → completed)")
  void saveUpsertsByTenant() {
    store.save(BootstrapState.required(TenantId.DEFAULT));
    Instant at = Instant.parse("2026-01-01T12:00:00Z");
    BootstrapState completed = BootstrapState.completed(TenantId.DEFAULT, at);
    store.save(completed);
    assertEquals(Optional.of(completed), store.find(TenantId.DEFAULT));
  }

  @Test
  @DisplayName("states are tenant-scoped — different tenants hold independent records")
  void statesAreTenantScoped() {
    BootstrapState defaultState = BootstrapState.required(TenantId.DEFAULT);
    BootstrapState acmeState = BootstrapState.completed(ACME,
        Instant.parse("2026-01-01T12:00:00Z"));
    store.save(defaultState);
    store.save(acmeState);
    assertEquals(Optional.of(defaultState), store.find(TenantId.DEFAULT));
    assertEquals(Optional.of(acmeState), store.find(ACME));
  }

  @Test
  @DisplayName("delete removes a present state and returns true")
  void deletePresent() {
    store.save(BootstrapState.required(TenantId.DEFAULT));
    assertTrue(store.delete(TenantId.DEFAULT));
    assertTrue(store.find(TenantId.DEFAULT).isEmpty());
  }

  @Test
  @DisplayName("delete on an unknown tenant returns false")
  void deleteUnknown() {
    assertFalse(store.delete(TenantId.DEFAULT));
  }

  @Test
  @DisplayName("find / save / delete reject null arguments")
  void rejectNulls() {
    assertThrows(NullPointerException.class, () -> store.find(null));
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertThrows(NullPointerException.class, () -> store.delete(null));
  }
}
