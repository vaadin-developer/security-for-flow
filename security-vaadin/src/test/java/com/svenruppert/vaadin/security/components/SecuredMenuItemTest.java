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
import com.vaadin.flow.component.contextmenu.MenuItem;
import com.vaadin.flow.component.menubar.MenuBar;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SecuredMenuItem")
class SecuredMenuItemTest {

  private static final RoleName ADMIN = new RoleName("ADMIN");

  private static Optional<SecuredVisibility.SecurityView> view(Set<RoleName> roles,
                                                               Set<PermissionName> perms) {
    HasRoles r = () -> List.copyOf(roles);
    HasPermissions p = () -> List.copyOf(perms);
    return Optional.of(new SecuredVisibility.SecurityView(r, p));
  }

  private static MenuItem freshItem() {
    return new MenuBar().addItem("Delete");
  }

  @Test
  @DisplayName("admitted subject → item stays visible + enabled")
  void admitted() {
    MenuItem item = freshItem();
    SecuredMenuItem.bind(item,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE,
        () -> view(Set.of(ADMIN), Set.of()));
    assertTrue(item.isVisible());
    assertTrue(item.isEnabled());
  }

  @Test
  @DisplayName("denied + HIDE (default) → item invisible")
  void deniedHide() {
    MenuItem item = freshItem();
    SecuredMenuItem secured = SecuredMenuItem.bind(item,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE,
        () -> view(Set.of(), Set.of()));
    assertFalse(item.isVisible());
    assertEquals(SecuredVisibilityMode.HIDE, secured.mode());
    assertSame(item, secured.menuItem());
  }

  @Test
  @DisplayName("denied + DISABLE → item visible but disabled")
  void deniedDisable() {
    MenuItem item = freshItem();
    SecuredMenuItem.bind(item,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.DISABLE,
        () -> view(Set.of(), Set.of()));
    assertTrue(item.isVisible());
    assertFalse(item.isEnabled());
  }

  @Test
  @DisplayName("refresh() recomputes against the current view")
  void refreshRecomputes() {
    MenuItem item = freshItem();
    AtomicReference<Optional<SecuredVisibility.SecurityView>> ref =
        new AtomicReference<>(view(Set.of(), Set.of()));
    SecuredMenuItem secured = SecuredMenuItem.bind(item,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE, ref::get);
    assertFalse(item.isVisible());

    ref.set(view(Set.of(ADMIN), Set.of()));
    secured.refresh();
    assertTrue(item.isVisible());
  }

  @Test
  @DisplayName("bind(2-arg) defaults to HIDE")
  void twoArgDefaultsToHide() {
    MenuItem item = freshItem();
    SecuredMenuItem secured = SecuredMenuItem.bind(item,
        SecuredVisibility.Requirement.role(ADMIN));
    // SPI-empty → denied → hidden
    assertFalse(item.isVisible());
    assertEquals(SecuredVisibilityMode.HIDE, secured.mode());
  }

  @Test
  @DisplayName("null arguments are rejected")
  void rejectNulls() {
    MenuItem item = freshItem();
    assertThrows(NullPointerException.class,
        () -> SecuredMenuItem.bind(null, SecuredVisibility.Requirement.role(ADMIN)));
    assertThrows(NullPointerException.class,
        () -> SecuredMenuItem.bind(item, null));
    assertThrows(NullPointerException.class,
        () -> SecuredMenuItem.bind(item, SecuredVisibility.Requirement.role(ADMIN), null));
    assertThrows(NullPointerException.class,
        () -> SecuredMenuItem.bind(item,
            SecuredVisibility.Requirement.role(ADMIN),
            SecuredVisibilityMode.HIDE, null));
  }
}
