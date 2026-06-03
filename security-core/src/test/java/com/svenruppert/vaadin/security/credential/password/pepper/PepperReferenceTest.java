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
package com.svenruppert.vaadin.security.credential.password.pepper;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PepperReferenceTest {

  private static byte[] key32() {
    byte[] b = new byte[PepperReference.MIN_KEY_BYTES];
    Arrays.fill(b, (byte) 0x11);
    return b;
  }

  @Test
  @DisplayName("Constructor defensively copies the key bytes")
  void defensiveCopyOnConstruction() {
    byte[] source = key32();
    PepperReference ref = new PepperReference("k1", source);
    source[0] = (byte) 0xFF;
    assertEquals((byte) 0x11, ref.copyKey()[0]);
  }

  @Test
  @DisplayName("copyKey returns a fresh array each call")
  void copyKeyIsFresh() {
    PepperReference ref = new PepperReference("k1", key32());
    byte[] a = ref.copyKey();
    byte[] b = ref.copyKey();
    assertNotSame(a, b);
    assertArrayEquals(a, b);
  }

  @Test
  @DisplayName("toString redacts the key material (CWE-209 / CWE-522)")
  void toStringRedactsKey() {
    PepperReference ref = new PepperReference("pepper-2026-04", key32());
    String text = ref.toString();
    assertTrue(text.contains("pepper-2026-04"));
    assertTrue(text.contains("keyLength=32"));
    assertTrue(text.contains("<redacted>"));
    assertFalse(text.contains("0x11"));
  }

  @Test
  @DisplayName("Constructor rejects short keys, null keyId, null key and blank keyId")
  void invariants() {
    assertThrows(NullPointerException.class,
        () -> new PepperReference(null, key32()));
    assertThrows(IllegalArgumentException.class,
        () -> new PepperReference(" ", key32()));
    assertThrows(NullPointerException.class,
        () -> new PepperReference("k1", null));
    assertThrows(IllegalArgumentException.class,
        () -> new PepperReference("k1", new byte[31]));
  }

  @Test
  @DisplayName("equals / hashCode consider keyId and bytes together")
  void equalsAndHashCode() {
    PepperReference a = new PepperReference("k1", key32());
    PepperReference b = new PepperReference("k1", key32());
    PepperReference c = new PepperReference("k2", key32());
    byte[] otherBytes = new byte[PepperReference.MIN_KEY_BYTES];
    Arrays.fill(otherBytes, (byte) 0x22);
    PepperReference d = new PepperReference("k1", otherBytes);
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    assertNotEquals(a, c);
    assertNotEquals(a, d);
  }
}
