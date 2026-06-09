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

import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PermissionMatcherContainsAnyTest {

  @Test
  @DisplayName("returns true when at least one required permission is held")
  void anyMatch() {
    assertTrue(PermissionMatcher.containsAny(
        List.of(new PermissionName("a")),
        Set.of(new PermissionName("a"), new PermissionName("b"))));
  }

  @Test
  @DisplayName("returns false when no required permission is held")
  void noneMatch() {
    assertFalse(PermissionMatcher.containsAny(
        List.of(new PermissionName("x")),
        Set.of(new PermissionName("a"), new PermissionName("b"))));
  }

  @Test
  @DisplayName("returns false for an empty required set")
  void emptyRequiredFalse() {
    assertFalse(PermissionMatcher.containsAny(
        List.of(new PermissionName("a")),
        Set.of()));
  }

  @Test
  @DisplayName("returns false for an empty granted set")
  void emptyGrantedFalse() {
    assertFalse(PermissionMatcher.containsAny(
        List.of(),
        Set.of(new PermissionName("a"))));
  }

  @Test
  @DisplayName("matches via wildcard granted permission")
  void wildcardGranted() {
    assertTrue(PermissionMatcher.containsAny(
        List.of(new PermissionName("doc:*")),
        Set.of(new PermissionName("doc:read"))));
  }
}
