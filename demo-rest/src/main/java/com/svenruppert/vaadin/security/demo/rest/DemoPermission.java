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
package com.svenruppert.vaadin.security.demo.rest;

import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;

/**
 * Demo-only REST permissions.
 */
public enum DemoPermission {
  DOCUMENT_READ("document:read"),
  DOCUMENT_CREATE("document:create"),
  DOCUMENT_UPDATE("document:update"),
  DOCUMENT_DELETE("document:delete"),
  ADMIN_ACCESS("admin:access");

  private final PermissionName permissionName;

  DemoPermission(String value) {
    this.permissionName = new PermissionName(value);
  }

  /**
   * Returns the permission name.
   *
   * @return permission name
   */
  public PermissionName permissionName() {
    return permissionName;
  }
}
