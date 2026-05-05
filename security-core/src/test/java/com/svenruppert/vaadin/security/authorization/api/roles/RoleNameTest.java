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
package com.svenruppert.vaadin.security.authorization.api.roles;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("RoleName and RoleMatcher")
class RoleNameTest {

  @Test
  @DisplayName("blank role name is rejected")
  void blankRejected() {
    assertThrows(IllegalArgumentException.class, () -> new RoleName(" "));
  }

  @Test
  @DisplayName("value returns role identifier")
  void valueAlias() {
    assertEquals("ROLE_ADMIN", new RoleName("ROLE_ADMIN").value());
  }

  @Test
  @DisplayName("containsAny requires at least one requested role")
  void containsAny() {
    assertTrue(RoleMatcher.containsAny(
        Set.of(new RoleName("ROLE_ADMIN")),
        Set.of(new RoleName("ROLE_VIEWER"), new RoleName("ROLE_ADMIN"))));
    assertFalse(RoleMatcher.containsAny(
        Set.of(new RoleName("ROLE_VIEWER")),
        Set.of(new RoleName("ROLE_ADMIN"))));
  }
}
