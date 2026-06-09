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
package com.svenruppert.jsentinel.components;

import com.svenruppert.jsentinel.authorization.api.permissions.HasPermissions;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.roles.HasRoles;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.vaadin.flow.component.Component;
import com.vaadin.flow.router.Route;
import com.vaadin.flow.router.Router;
import com.vaadin.flow.router.internal.AbstractRouteRegistry;
import com.vaadin.flow.server.VaadinContext;
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

@DisplayName("SecuredRouterLink")
class SecuredRouterLinkTest {

  private static final RoleName ADMIN = new RoleName("ADMIN");

  @Route("dummy")
  static class Dummy extends Component {}

  /** Headless router stub used in place of the VaadinService-bound router. */
  private static final Router ROUTER = router();

  private static Router router() {
    TestRouteRegistry reg = new TestRouteRegistry();
    reg.setRoute("dummy", Dummy.class, java.util.List.of());
    return new Router(reg);
  }

  private static final class TestRouteRegistry extends AbstractRouteRegistry {
    @Override public VaadinContext getContext() { return null; }
  }

  private static Optional<SecuredVisibility.JSentinelView> view(Set<RoleName> roles,
                                                               Set<PermissionName> perms) {
    HasRoles r = () -> List.copyOf(roles);
    HasPermissions p = () -> List.copyOf(perms);
    return Optional.of(new SecuredVisibility.JSentinelView(r, p));
  }

  @Test
  @DisplayName("default mode is HIDE")
  void defaultModeIsHide() {
    SecuredRouterLink link = new SecuredRouterLink(ROUTER, "Admin", Dummy.class,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE,
        () -> view(Set.of(), Set.of()));
    assertFalse(link.isVisible());
    assertEquals(SecuredVisibilityMode.HIDE, link.mode());
  }

  @Test
  @DisplayName("admitted subject → link visible + enabled")
  void admittedShowsLink() {
    SecuredRouterLink link = new SecuredRouterLink(ROUTER, "Admin", Dummy.class,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE,
        () -> view(Set.of(ADMIN), Set.of()));
    assertTrue(link.isVisible());
    assertTrue(link.isEnabled());
  }

  @Test
  @DisplayName("denied + DISABLE → visible but disabled")
  void disableMode() {
    SecuredRouterLink link = new SecuredRouterLink(ROUTER, "Admin", Dummy.class,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.DISABLE,
        () -> view(Set.of(), Set.of()));
    assertTrue(link.isVisible());
    assertFalse(link.isEnabled());
  }

  @Test
  @DisplayName("refresh() recomputes against the current view")
  void refreshRecomputes() {
    AtomicReference<Optional<SecuredVisibility.JSentinelView>> ref =
        new AtomicReference<>(view(Set.of(), Set.of()));
    SecuredRouterLink link = new SecuredRouterLink(ROUTER, "Admin", Dummy.class,
        SecuredVisibility.Requirement.role(ADMIN),
        SecuredVisibilityMode.HIDE, ref::get);
    assertFalse(link.isVisible());

    ref.set(view(Set.of(ADMIN), Set.of()));
    link.refresh();
    assertTrue(link.isVisible());
  }

  @Test
  @DisplayName("requirement / mode accessors expose constructor arguments")
  void accessors() {
    SecuredVisibility.Requirement req = SecuredVisibility.Requirement.role(ADMIN);
    SecuredRouterLink link = new SecuredRouterLink(ROUTER, "X", Dummy.class, req,
        SecuredVisibilityMode.DISABLE, Optional::empty);
    assertSame(req, link.requirement());
    assertEquals(SecuredVisibilityMode.DISABLE, link.mode());
  }

  @Test
  @DisplayName("null arguments are rejected by the router-explicit constructor")
  void rejectNulls() {
    assertThrows(NullPointerException.class,
        () -> new SecuredRouterLink(null, "X", Dummy.class,
            SecuredVisibility.Requirement.role(ADMIN),
            SecuredVisibilityMode.HIDE, Optional::empty));
    assertThrows(NullPointerException.class,
        () -> new SecuredRouterLink(ROUTER, null, Dummy.class,
            SecuredVisibility.Requirement.role(ADMIN),
            SecuredVisibilityMode.HIDE, Optional::empty));
    assertThrows(NullPointerException.class,
        () -> new SecuredRouterLink(ROUTER, "X", null,
            SecuredVisibility.Requirement.role(ADMIN),
            SecuredVisibilityMode.HIDE, Optional::empty));
    assertThrows(NullPointerException.class,
        () -> new SecuredRouterLink(ROUTER, "X", Dummy.class,
            null,
            SecuredVisibilityMode.HIDE, Optional::empty));
    assertThrows(NullPointerException.class,
        () -> new SecuredRouterLink(ROUTER, "X", Dummy.class,
            SecuredVisibility.Requirement.role(ADMIN),
            null, Optional::empty));
    assertThrows(NullPointerException.class,
        () -> new SecuredRouterLink(ROUTER, "X", Dummy.class,
            SecuredVisibility.Requirement.role(ADMIN),
            SecuredVisibilityMode.HIDE, null));
  }
}
