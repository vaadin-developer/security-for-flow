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
package com.svenruppert.jsentinel.authorization.api.permissions;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("PermissionName and PermissionMatcher")
class PermissionNameTest {

  @Test
  @DisplayName("blank permission name is rejected")
  void blankRejected() {
    assertThrows(IllegalArgumentException.class, () -> new PermissionName(" "));
  }

  @Test
  @DisplayName("value returns permission identifier")
  void valueAlias() {
    assertEquals("document:read", new PermissionName("document:read").value());
  }

  @Test
  @DisplayName("exact and terminal wildcard permissions match")
  void wildcardMatches() {
    assertTrue(PermissionMatcher.matches(
        new PermissionName("document:*"),
        new PermissionName("document:delete")));
    assertFalse(PermissionMatcher.matches(
        new PermissionName("admin:*"),
        new PermissionName("document:delete")));
  }

  @Test
  @DisplayName("containsAll requires every requested permission")
  void containsAll() {
    assertTrue(PermissionMatcher.containsAll(
        Set.of(new PermissionName("document:*")),
        Set.of(new PermissionName("document:read"), new PermissionName("document:delete"))));
    assertFalse(PermissionMatcher.containsAll(
        Set.of(new PermissionName("document:read")),
        Set.of(new PermissionName("document:read"), new PermissionName("document:delete"))));
  }
}
