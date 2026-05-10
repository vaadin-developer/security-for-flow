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
package com.svenruppert.vaadin.security.action;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ActionPermissionTest {

  @Test
  @DisplayName("constructor rejects null name")
  void rejectsNullName() {
    assertThrows(NullPointerException.class, () -> new ActionPermission(null));
  }

  @Test
  @DisplayName("constructor rejects blank name")
  void rejectsBlankName() {
    assertThrows(IllegalArgumentException.class, () -> new ActionPermission("   "));
    assertThrows(IllegalArgumentException.class, () -> new ActionPermission(""));
  }

  @Test
  @DisplayName("name() returns the constructor argument verbatim")
  void preservesName() {
    assertEquals("USER_DELETE", new ActionPermission("USER_DELETE").name());
  }

  @Test
  @DisplayName("equality is structural — same name produces equal records")
  void equality() {
    assertEquals(new ActionPermission("X"), new ActionPermission("X"));
    assertNotEquals(new ActionPermission("X"), new ActionPermission("Y"));
  }
}
