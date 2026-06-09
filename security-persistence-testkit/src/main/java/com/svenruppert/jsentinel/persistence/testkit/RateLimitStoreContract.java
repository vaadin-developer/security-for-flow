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
package com.svenruppert.jsentinel.persistence.testkit;

import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.ratelimiting.RateLimitKey;
import com.svenruppert.jsentinel.ratelimiting.RateLimitStore;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Contract every {@link RateLimitStore} implementation must satisfy.
 */
@DisplayName("RateLimitStore — contract")
public interface RateLimitStoreContract {

  /**
   * @return a fresh, empty {@code RateLimitStore}
   */
  RateLimitStore newStore();

  Instant T0 = Instant.parse("2026-01-01T00:00:00Z");

  /**
   * Builds a key in the default tenant.
   *
   * @param scope scope string
   * @return new key
   */
  default RateLimitKey key(String scope) {
    return new RateLimitKey(TenantId.DEFAULT, scope);
  }

  @Test
  @DisplayName("countSince on an unknown key returns 0")
  default void unknownKeyZero() {
    RateLimitStore store = newStore();
    assertEquals(0, store.countSince(key("ip:1.2.3.4"), T0));
  }

  @Test
  @DisplayName("recordEvent + countSince — counts at-or-after the cutoff")
  default void countAtOrAfter() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);
    store.recordEvent(k, T0.plusSeconds(10));
    store.recordEvent(k, T0.plusSeconds(20));
    store.recordEvent(k, T0.plusSeconds(30));

    assertEquals(2, store.countSince(k, T0.plusSeconds(15)));
    assertEquals(2, store.countSince(k, T0.plusSeconds(20)));
    assertEquals(0, store.countSince(k, T0.plusSeconds(40)));
  }

  @Test
  @DisplayName("keys are isolated")
  default void keysAreIsolated() {
    RateLimitStore store = newStore();
    RateLimitKey a = key("ip:1.2.3.4");
    RateLimitKey b = key("ip:5.6.7.8");
    store.recordEvent(a, T0);
    store.recordEvent(a, T0.plusSeconds(10));
    store.recordEvent(b, T0);

    assertEquals(2, store.countSince(a, T0));
    assertEquals(1, store.countSince(b, T0));
  }

  @Test
  @DisplayName("tenant is part of the key")
  default void tenantScoped() {
    RateLimitStore store = newStore();
    RateLimitKey defaultScope = new RateLimitKey(TenantId.DEFAULT, "ip:1.2.3.4");
    RateLimitKey acmeScope = new RateLimitKey(new TenantId("acme"), "ip:1.2.3.4");
    store.recordEvent(defaultScope, T0);
    store.recordEvent(acmeScope, T0);
    store.recordEvent(acmeScope, T0.plusSeconds(10));

    assertEquals(1, store.countSince(defaultScope, T0));
    assertEquals(2, store.countSince(acmeScope, T0));
  }

  @Test
  @DisplayName("reset drops every event under the key")
  default void resetClears() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);
    store.recordEvent(k, T0.plusSeconds(10));
    store.reset(k);
    assertEquals(0, store.countSince(k, T0));
  }

  @Test
  @DisplayName("reset on unknown is a no-op")
  default void resetUnknown() {
    RateLimitStore store = newStore();
    store.reset(key("ghost"));
    assertEquals(0, store.countSince(key("ghost"), T0));
  }

  @Test
  @DisplayName("purgeOlderThan drops events strictly before the cutoff; at-cutoff survives")
  default void purgeStrictlyBefore() {
    RateLimitStore store = newStore();
    RateLimitKey k = key("ip:1.2.3.4");
    store.recordEvent(k, T0);                       // before
    store.recordEvent(k, T0.plusSeconds(10));       // at cutoff
    store.recordEvent(k, T0.plusSeconds(20));       // after

    assertEquals(1, store.purgeOlderThan(T0.plusSeconds(10)));
    assertEquals(2, store.countSince(k, T0.plusSeconds(10)));
  }

  @Test
  @DisplayName("purgeOlderThan on an empty store returns 0")
  default void purgeEmpty() {
    RateLimitStore store = newStore();
    assertEquals(0, store.purgeOlderThan(T0.plusSeconds(10)));
  }

  @Test
  @DisplayName("all methods reject null arguments")
  default void rejectNulls() {
    RateLimitStore store = newStore();
    assertThrows(NullPointerException.class, () -> store.recordEvent(null, T0));
    assertThrows(NullPointerException.class,
        () -> store.recordEvent(key("ip:1.2.3.4"), null));
    assertThrows(NullPointerException.class, () -> store.countSince(null, T0));
    assertThrows(NullPointerException.class,
        () -> store.countSince(key("ip:1.2.3.4"), null));
    assertThrows(NullPointerException.class, () -> store.reset(null));
    assertThrows(NullPointerException.class, () -> store.purgeOlderThan(null));
  }
}
