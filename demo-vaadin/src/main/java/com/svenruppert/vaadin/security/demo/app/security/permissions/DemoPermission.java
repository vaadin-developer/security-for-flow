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
package com.svenruppert.vaadin.security.demo.app.security.permissions;

import com.svenruppert.vaadin.security.action.ActionPermission;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;

/**
 * Demo-only Vaadin permissions.
 */
public enum DemoPermission {
  DEMO_VIEW("demo:view"),
  DEMO_EDIT("demo:edit"),
  DEMO_ADMIN("demo:admin"),
  AUDIT_READ("audit:read"),
  ADMIN_ROLES("admin:roles"),
  ADMIN_SESSIONS("admin:sessions");

  private final PermissionName permissionName;
  private final ActionPermission actionPermission;

  DemoPermission(String value) {
    this.permissionName = new PermissionName(value);
    this.actionPermission = new ActionPermission(value);
  }

  /**
   * Returns the permission name used for route- and permission-level checks.
   */
  public PermissionName permissionName() {
    return permissionName;
  }

  /**
   * Returns the matching {@link ActionPermission} used for fine-grained
   * action checks through {@code ActionAuthorizationService}. The same
   * string value backs both names — see
   * {@code StaticActionAuthorizationService#isAllowed}.
   */
  public ActionPermission actionPermission() {
    return actionPermission;
  }
}
