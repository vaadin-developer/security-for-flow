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
package eu.jsentinel.jcustos.persistence.testkit;

import eu.jsentinel.jcustos.authorization.api.tenant.TenantId;
import eu.jsentinel.jcustos.bootstrap.BootstrapState;
import eu.jsentinel.jcustos.bootstrap.BootstrapStateStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Contract every {@link BootstrapStateStore} implementation must
 * satisfy.
 */
@DisplayName("BootstrapStateStore — contract")
public interface BootstrapStateStoreContract {

  /**
   * @return a fresh, empty {@code BootstrapStateStore}
   */
  BootstrapStateStore newStore();

  @Test
  @DisplayName("find on an unknown tenant returns empty")
  default void findUnknownEmpty() {
    BootstrapStateStore store = newStore();
    assertTrue(store.find(TenantId.DEFAULT).isEmpty());
  }

  @Test
  @DisplayName("save persists state retrievable by tenant")
  default void saveAndFind() {
    BootstrapStateStore store = newStore();
    BootstrapState state = BootstrapState.required(TenantId.DEFAULT);
    store.save(state);
    assertEquals(Optional.of(state), store.find(TenantId.DEFAULT));
  }

  @Test
  @DisplayName("save upserts on the tenant key — transition required → completed")
  default void saveUpserts() {
    BootstrapStateStore store = newStore();
    store.save(BootstrapState.required(TenantId.DEFAULT));
    Instant at = Instant.parse("2026-01-01T12:00:00Z");
    BootstrapState completed = BootstrapState.completed(TenantId.DEFAULT, at);
    store.save(completed);
    assertEquals(Optional.of(completed), store.find(TenantId.DEFAULT));
  }

  @Test
  @DisplayName("states are tenant-scoped — different tenants hold independent records")
  default void tenantScoped() {
    BootstrapStateStore store = newStore();
    TenantId acme = new TenantId("acme");
    BootstrapState defaultState = BootstrapState.required(TenantId.DEFAULT);
    BootstrapState acmeState = BootstrapState.completed(acme,
        Instant.parse("2026-01-01T12:00:00Z"));
    store.save(defaultState);
    store.save(acmeState);
    assertEquals(Optional.of(defaultState), store.find(TenantId.DEFAULT));
    assertEquals(Optional.of(acmeState), store.find(acme));
  }

  @Test
  @DisplayName("delete removes a present state; unknown tenant returns false")
  default void deleteLifecycle() {
    BootstrapStateStore store = newStore();
    store.save(BootstrapState.required(TenantId.DEFAULT));
    assertTrue(store.delete(TenantId.DEFAULT));
    assertTrue(store.find(TenantId.DEFAULT).isEmpty());
    assertFalse(store.delete(TenantId.DEFAULT));
  }

  @Test
  @DisplayName("find / save / delete reject null arguments")
  default void rejectNulls() {
    BootstrapStateStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.find(null));
    assertThrows(NullPointerException.class, () -> store.save(null));
    assertThrows(NullPointerException.class, () -> store.delete(null));
  }
}
