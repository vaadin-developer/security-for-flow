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
package com.svenruppert.vaadin.security.demo.standalone;

import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;

/** Demo-only permissions for the standalone CLI. */
public enum Permission {
  BOOK_LIST("book:list"),
  BOOK_BORROW("book:borrow"),
  BOOK_RETURN("book:return"),
  BOOK_ADD("book:add"),
  BOOK_REMOVE("book:remove");

  private final PermissionName permissionName;

  Permission(String value) {
    this.permissionName = new PermissionName(value);
  }

  public PermissionName permissionName() {
    return permissionName;
  }
}
