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
package eu.jsentinel.jcustos.oauth2.vaadin;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import eu.jsentinel.jcustos.oauth2.api.StateEntry;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("VaadinSessionStateStore — no-active-session guard paths (no mocks)")
class VaadinSessionStateStoreTest {

  private final VaadinSessionStateStore store = new VaadinSessionStateStore();

  private static StateEntry entry() {
    return new StateEntry("pkce-verifier", Optional.empty(), Optional.<URI>empty(),
        Map.of(), Instant.parse("2026-06-26T10:00:00Z"));
  }

  @Test
  @DisplayName("bind without an active VaadinSession throws")
  void bindWithoutSessionThrows() {
    IllegalStateException ex = assertThrows(IllegalStateException.class,
        () -> store.bind("state-1", entry(), Duration.ofMinutes(5)));
    assertTrue(ex.getMessage().contains("VaadinSession"));
  }

  @Test
  @DisplayName("consume without an active VaadinSession returns empty (never throws)")
  void consumeWithoutSessionEmpty() {
    assertTrue(store.consume("state-1").isEmpty());
  }

  @Test
  @DisplayName("clear without an active VaadinSession is a no-op")
  void clearWithoutSessionNoop() {
    assertDoesNotThrow(store::clear);
  }
}
