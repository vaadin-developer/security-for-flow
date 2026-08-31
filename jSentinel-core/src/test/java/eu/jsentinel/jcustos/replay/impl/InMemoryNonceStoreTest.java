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
package eu.jsentinel.jcustos.replay.impl;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("InMemoryNonceStore")
class InMemoryNonceStoreTest {

  private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  @Test
  @DisplayName("bind + single-use consume round-trip")
  void bindConsumeRoundTrip() {
    InMemoryNonceStore store = new InMemoryNonceStore(() -> T0);
    store.bind("req-1", "nonce-abc", Duration.ofMinutes(10));
    assertEquals(Optional.of("nonce-abc"), store.consume("req-1"));
    assertTrue(store.consume("req-1").isEmpty(), "consume is single-use");
  }

  @Test
  @DisplayName("JS-SEC-051: a map full of live bindings rejects a new key with a capacity-exceeded error")
  void fullOfLiveThrows() {
    int cap = 20;
    InMemoryNonceStore store = new InMemoryNonceStore(() -> T0, cap);
    for (int i = 0; i < cap; i++) {
      store.bind("k-" + i, "n", Duration.ofMinutes(10));
    }
    IllegalStateException ex = assertThrows(IllegalStateException.class,
        () -> store.bind("overflow", "n", Duration.ofMinutes(10)));
    assertTrue(ex.getMessage().contains("replay/nonce-store-capacity-exceeded"), ex.getMessage());
  }

  @Test
  @DisplayName("JS-SEC-051: a full-but-expired map is purged so a new binding succeeds")
  void fullOfExpiredIsPurged() {
    int cap = 20;
    AtomicReference<Instant> now = new AtomicReference<>(T0);
    InMemoryNonceStore store = new InMemoryNonceStore(now::get, cap);
    for (int i = 0; i < cap; i++) {
      store.bind("k-" + i, "n", Duration.ofSeconds(1));
    }
    now.set(T0.plusSeconds(60)); // every binding is now expired
    store.bind("fresh", "n", Duration.ofMinutes(10));
    assertEquals(1, store.trackedKeyCount(), "the expired bindings were reclaimed");
  }
}
