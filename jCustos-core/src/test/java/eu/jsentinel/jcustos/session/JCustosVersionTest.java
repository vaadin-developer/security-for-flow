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
package eu.jsentinel.jcustos.session;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("JCustosVersion")
class JCustosVersionTest {

  @Test
  @DisplayName("constructor rejects negative values")
  void rejectsNegative() {
    assertThrows(IllegalArgumentException.class, () -> new JCustosVersion(-1));
    assertThrows(IllegalArgumentException.class, () -> new JCustosVersion(Long.MIN_VALUE));
  }

  @Test
  @DisplayName("constructor accepts zero (the initial version)")
  void acceptsZero() {
    assertEquals(0L, new JCustosVersion(0).value());
  }

  @Test
  @DisplayName("constructor accepts large positive values")
  void acceptsPositive() {
    assertEquals(Long.MAX_VALUE, new JCustosVersion(Long.MAX_VALUE).value());
  }

  @Test
  @DisplayName("INITIAL is value zero")
  void initialIsZero() {
    assertEquals(0L, JCustosVersion.INITIAL.value());
  }

  @Test
  @DisplayName("INITIAL is a constant — same instance on every reference")
  void initialIsSingleton() {
    assertSame(JCustosVersion.INITIAL, JCustosVersion.INITIAL);
  }

  @Test
  @DisplayName("next() returns value + 1 without mutating the receiver")
  void nextIncrements() {
    JCustosVersion three = new JCustosVersion(3);
    JCustosVersion four = three.next();
    assertEquals(4L, four.value());
    assertEquals(3L, three.value(), "next() must be pure — receiver unchanged");
  }

  @Test
  @DisplayName("equals is value-based")
  void equalsIsValueBased() {
    assertEquals(new JCustosVersion(7), new JCustosVersion(7));
    assertNotEquals(new JCustosVersion(7), new JCustosVersion(8));
  }

  @Test
  @DisplayName("compareTo orders by value")
  void compareTo() {
    assertTrue(new JCustosVersion(1).compareTo(new JCustosVersion(2)) < 0);
    assertTrue(new JCustosVersion(5).compareTo(new JCustosVersion(2)) > 0);
    assertEquals(0, new JCustosVersion(3).compareTo(new JCustosVersion(3)));
  }
}
