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

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@DisplayName("Permission")
class PermissionTest {

  @Test
  @DisplayName("each constant exposes a PermissionName whose value matches the colon-form identifier")
  void everyPermissionExposesItsName() {
    assertEquals("book:list", Permission.BOOK_LIST.permissionName().value());
    assertEquals("book:borrow", Permission.BOOK_BORROW.permissionName().value());
    assertEquals("book:return", Permission.BOOK_RETURN.permissionName().value());
    assertEquals("book:add", Permission.BOOK_ADD.permissionName().value());
    assertEquals("book:remove", Permission.BOOK_REMOVE.permissionName().value());
  }

  @Test
  @DisplayName("permissionName() never returns null")
  void permissionNameIsNotNull() {
    for (Permission p : Permission.values()) {
      assertNotNull(p.permissionName(),
          "permissionName() must not return null for " + p);
    }
  }
}
