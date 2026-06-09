/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
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
package com.svenruppert.jsentinel.credential.password.pepper;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class InMemoryPepperServiceTest {

  private static byte[] key32(byte fill) {
    byte[] b = new byte[PepperReference.MIN_KEY_BYTES];
    Arrays.fill(b, fill);
    return b;
  }

  @Test
  @DisplayName("withActiveKey reports a present active key id")
  void withActiveKeyReportsActive() {
    InMemoryPepperService svc = InMemoryPepperService.withActiveKey(
        "k1", key32((byte) 0x11));
    assertEquals("k1", svc.activeKeyId().orElseThrow());
    assertTrue(svc.resolve("k1").isPresent());
  }

  @Test
  @DisplayName("resolve returns a defensive copy each call")
  void resolveDefensiveCopy() {
    InMemoryPepperService svc = InMemoryPepperService.withActiveKey(
        "k1", key32((byte) 0x11));
    byte[] a = svc.resolve("k1").orElseThrow();
    byte[] b = svc.resolve("k1").orElseThrow();
    assertNotSame(a, b);
    assertArrayEquals(a, b);
    a[0] = (byte) 0xFF;
    assertEquals((byte) 0x11, svc.resolve("k1").orElseThrow()[0]);
  }

  @Test
  @DisplayName("resolve returns empty for unknown key ids")
  void resolveUnknown() {
    InMemoryPepperService svc = InMemoryPepperService.withActiveKey(
        "k1", key32((byte) 0x11));
    assertFalse(svc.resolve("k2").isPresent());
  }

  @Test
  @DisplayName("withActiveKey rejects short keys")
  void rejectsShortKey() {
    assertThrows(IllegalArgumentException.class,
        () -> InMemoryPepperService.withActiveKey("k1", new byte[16]));
  }

  @Test
  @DisplayName("Builder accepts multiple keys with one declared active")
  void builderMultiKey() {
    InMemoryPepperService svc = InMemoryPepperService.builder()
        .addKey("retired", key32((byte) 0x22))
        .addKey("active", key32((byte) 0x33))
        .activeKeyId("active")
        .build();
    assertEquals("active", svc.activeKeyId().orElseThrow());
    assertTrue(svc.resolve("retired").isPresent());
    assertTrue(svc.resolve("active").isPresent());
    assertEquals(2, svc.knownKeyCount());
  }

  @Test
  @DisplayName("Builder rejects duplicate key ids")
  void builderRejectsDuplicateIds() {
    InMemoryPepperService.Builder builder = InMemoryPepperService.builder()
        .addKey("k1", key32((byte) 0x11));
    assertThrows(IllegalArgumentException.class,
        () -> builder.addKey("k1", key32((byte) 0x22)));
  }

  @Test
  @DisplayName("Builder rejects an active id that was not added")
  void builderRejectsUnknownActive() {
    InMemoryPepperService.Builder b = InMemoryPepperService.builder()
        .addKey("k1", key32((byte) 0x11))
        .activeKeyId("k-ghost");
    assertThrows(IllegalStateException.class, b::build);
  }

  @Test
  @DisplayName("wipe forgets every key and zeros the storage")
  void wipeForgets() {
    InMemoryPepperService svc = InMemoryPepperService.withActiveKey(
        "k1", key32((byte) 0x11));
    svc.wipe();
    assertEquals(0, svc.knownKeyCount());
    assertFalse(svc.resolve("k1").isPresent());
  }
}
