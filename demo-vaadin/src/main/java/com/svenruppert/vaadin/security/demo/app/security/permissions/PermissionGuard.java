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

import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.authorization.api.permissions.HasPermissions;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;

import java.util.Optional;

/**
 * Demo-side adapter around the generic
 * {@link com.svenruppert.vaadin.security.authorization.api.PermissionGuard}.
 * Reads the current Vaadin-session user, asks the authorization service for
 * its permissions, and delegates the actual decision to the generic guard.
 */
public final class PermissionGuard {

  private PermissionGuard() {
  }

  public static boolean hasPermission(PermissionName permission) {
    return com.svenruppert.vaadin.security.authorization.api.PermissionGuard
        .hasPermission(currentSubject(), permission);
  }

  public static void requirePermission(PermissionName permission) {
    com.svenruppert.vaadin.security.authorization.api.PermissionGuard
        .requirePermission(currentSubject(), permission);
  }

  /** Builds a {@link HasPermissions} view of the currently logged-in user, or empty. */
  private static HasPermissions currentSubject() {
    Optional<MyUser> user = SubjectStores.subjectStore().currentSubject(MyUser.class);
    if (user.isEmpty()) return java.util.Collections::emptyList;
    AuthorizationService<MyUser> auth = SecurityServiceResolver.authorizationService();
    return auth.permissionsFor(user.get());
  }
}
