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
package com.svenruppert.vaadin.security.components;

import com.svenruppert.vaadin.security.authorization.api.permissions.HasPermissions;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.HasRoles;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SecuredButton")
class SecuredButtonTest {

  private static final RoleName ADMIN = new RoleName("ADMIN");
  private static final PermissionName DOC_DELETE = new PermissionName("document:delete");

  private static Optional<SecuredVisibility.JSentinelView> view(Set<RoleName> roles,
                                                               Set<PermissionName> perms) {
    HasRoles r = () -> List.copyOf(roles);
    HasPermissions p = () -> List.copyOf(perms);
    return Optional.of(new SecuredVisibility.JSentinelView(r, p));
  }

  @Test
  @DisplayName("admitted subject → button stays visible and enabled")
  void admittedKeepsButton() {
    SecuredButton btn = new SecuredButton("Delete",
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.DISABLE,
        () -> view(Set.of(ADMIN), Set.of()));
    assertTrue(btn.isVisible());
    assertTrue(btn.isEnabled());
  }

  @Test
  @DisplayName("denied + DISABLE (default) → button visible but disabled")
  void deniedDisable() {
    SecuredButton btn = new SecuredButton("Delete",
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.DISABLE,
        () -> view(Set.of(), Set.of()));
    assertTrue(btn.isVisible());
    assertFalse(btn.isEnabled());
    assertEquals(SecuredVisibilityMode.DISABLE, btn.mode());
  }

  @Test
  @DisplayName("denied + HIDE → button invisible")
  void deniedHide() {
    SecuredButton btn = new SecuredButton("Delete",
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE,
        () -> view(Set.of(), Set.of()));
    assertFalse(btn.isVisible());
  }

  @Test
  @DisplayName("refresh() recomputes from the current security view")
  void refreshRecomputes() {
    java.util.concurrent.atomic.AtomicReference<Optional<SecuredVisibility.JSentinelView>> ref =
        new java.util.concurrent.atomic.AtomicReference<>(view(Set.of(), Set.of()));
    SecuredButton btn = new SecuredButton("Delete",
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE, ref::get);
    assertFalse(btn.isVisible());

    ref.set(view(Set.of(ADMIN), Set.of()));
    btn.refresh();
    assertTrue(btn.isVisible());

    ref.set(view(Set.of(), Set.of()));
    btn.refresh();
    assertFalse(btn.isVisible());
  }

  @Test
  @DisplayName("permission requirement honoured")
  void permissionRequirementHonoured() {
    SecuredButton btn = new SecuredButton("Delete",
        SecuredVisibility.Requirement.permission(DOC_DELETE),
        SecuredVisibilityMode.DISABLE,
        () -> view(Set.of(), Set.of(DOC_DELETE)));
    assertTrue(btn.isEnabled());
  }

  @Test
  @DisplayName("requirement / mode accessors expose constructor arguments")
  void accessors() {
    SecuredVisibility.Requirement req = SecuredVisibility.Requirement.role(ADMIN);
    SecuredButton btn = new SecuredButton("X", req, SecuredVisibilityMode.HIDE,
        Optional::empty);
    assertSame(req, btn.requirement());
    assertEquals(SecuredVisibilityMode.HIDE, btn.mode());
  }

  @Test
  @DisplayName("null arguments are rejected")
  void rejectNulls() {
    assertThrows(NullPointerException.class,
        () -> new SecuredButton(null, SecuredVisibility.Requirement.role(ADMIN)));
    assertThrows(NullPointerException.class,
        () -> new SecuredButton("X", null));
    assertThrows(NullPointerException.class,
        () -> new SecuredButton("X", SecuredVisibility.Requirement.role(ADMIN), null));
    assertThrows(NullPointerException.class,
        () -> new SecuredButton("X", SecuredVisibility.Requirement.role(ADMIN),
            SecuredVisibilityMode.HIDE, null));
  }
}
