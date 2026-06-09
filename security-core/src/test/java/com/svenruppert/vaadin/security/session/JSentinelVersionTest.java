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
package com.svenruppert.vaadin.security.session;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JSentinelVersion")
class JSentinelVersionTest {

  @Test
  @DisplayName("constructor rejects negative values")
  void rejectsNegative() {
    assertThrows(IllegalArgumentException.class, () -> new JSentinelVersion(-1));
    assertThrows(IllegalArgumentException.class, () -> new JSentinelVersion(Long.MIN_VALUE));
  }

  @Test
  @DisplayName("constructor accepts zero (the initial version)")
  void acceptsZero() {
    assertEquals(0L, new JSentinelVersion(0).value());
  }

  @Test
  @DisplayName("constructor accepts large positive values")
  void acceptsPositive() {
    assertEquals(Long.MAX_VALUE, new JSentinelVersion(Long.MAX_VALUE).value());
  }

  @Test
  @DisplayName("INITIAL is value zero")
  void initialIsZero() {
    assertEquals(0L, JSentinelVersion.INITIAL.value());
  }

  @Test
  @DisplayName("INITIAL is a constant — same instance on every reference")
  void initialIsSingleton() {
    assertSame(JSentinelVersion.INITIAL, JSentinelVersion.INITIAL);
  }

  @Test
  @DisplayName("next() returns value + 1 without mutating the receiver")
  void nextIncrements() {
    JSentinelVersion three = new JSentinelVersion(3);
    JSentinelVersion four = three.next();
    assertEquals(4L, four.value());
    assertEquals(3L, three.value(), "next() must be pure — receiver unchanged");
  }

  @Test
  @DisplayName("equals is value-based")
  void equalsIsValueBased() {
    assertEquals(new JSentinelVersion(7), new JSentinelVersion(7));
    assertNotEquals(new JSentinelVersion(7), new JSentinelVersion(8));
  }

  @Test
  @DisplayName("compareTo orders by value")
  void compareTo() {
    assertTrue(new JSentinelVersion(1).compareTo(new JSentinelVersion(2)) < 0);
    assertTrue(new JSentinelVersion(5).compareTo(new JSentinelVersion(2)) > 0);
    assertEquals(0, new JSentinelVersion(3).compareTo(new JSentinelVersion(3)));
  }
}
