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
package com.svenruppert.vaadin.security.test;

import com.svenruppert.vaadin.security.authorization.annotations.RequiresAllPermissions;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresAnyPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPolicy;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresRole;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

class SyntheticAnnotationsTest {

  @Test
  @DisplayName("requiresRole exposes the configured values + annotationType")
  void requiresRoleAnnotation() {
    RequiresRole ann = SyntheticAnnotations.requiresRole("ROLE_ADMIN", "ROLE_EDITOR");
    assertArrayEquals(new String[]{"ROLE_ADMIN", "ROLE_EDITOR"}, ann.value());
    assertSame(RequiresRole.class, ann.annotationType());
  }

  @Test
  @DisplayName("requiresPermission exposes the configured values + annotationType")
  void requiresPermissionAnnotation() {
    RequiresPermission ann = SyntheticAnnotations.requiresPermission("doc:read");
    assertArrayEquals(new String[]{"doc:read"}, ann.value());
    assertSame(RequiresPermission.class, ann.annotationType());
  }

  @Test
  @DisplayName("requiresAnyPermission exposes the configured values + annotationType")
  void requiresAnyPermissionAnnotation() {
    RequiresAnyPermission ann = SyntheticAnnotations.requiresAnyPermission("a", "b");
    assertArrayEquals(new String[]{"a", "b"}, ann.value());
    assertSame(RequiresAnyPermission.class, ann.annotationType());
  }

  @Test
  @DisplayName("requiresAllPermissions exposes the configured values + annotationType")
  void requiresAllPermissionsAnnotation() {
    RequiresAllPermissions ann = SyntheticAnnotations.requiresAllPermissions("a", "b");
    assertArrayEquals(new String[]{"a", "b"}, ann.value());
    assertSame(RequiresAllPermissions.class, ann.annotationType());
  }

  @Test
  @DisplayName("requiresPolicy exposes the configured value + annotationType")
  void requiresPolicyAnnotation() {
    RequiresPolicy ann = SyntheticAnnotations.requiresPolicy("doc.owner-or-admin");
    assertEquals("doc.owner-or-admin", ann.value());
    assertSame(RequiresPolicy.class, ann.annotationType());
  }
}
