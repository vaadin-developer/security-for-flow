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
package com.svenruppert.vaadin.security.logout;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SubjectIdTest {

  @Test
  @DisplayName("constructor rejects null value")
  void rejectsNullValue() {
    assertThrows(NullPointerException.class, () -> new SubjectId(null));
  }

  @Test
  @DisplayName("constructor rejects blank value")
  void rejectsBlankValue() {
    assertThrows(IllegalArgumentException.class, () -> new SubjectId("   "));
    assertThrows(IllegalArgumentException.class, () -> new SubjectId(""));
  }

  @Test
  @DisplayName("of(value) is a convenience factory equivalent to the canonical constructor")
  void factoryEqualsCanonical() {
    assertEquals(new SubjectId("alice"), SubjectId.of("alice"));
  }

  @Test
  @DisplayName("value() returns the constructor argument verbatim")
  void preservesValue() {
    assertEquals("alice", new SubjectId("alice").value());
  }

  @Test
  @DisplayName("equality is structural — same value produces equal SubjectIds")
  void equality() {
    assertEquals(new SubjectId("alice"), new SubjectId("alice"));
    assertNotEquals(new SubjectId("alice"), new SubjectId("bob"));
  }
}
