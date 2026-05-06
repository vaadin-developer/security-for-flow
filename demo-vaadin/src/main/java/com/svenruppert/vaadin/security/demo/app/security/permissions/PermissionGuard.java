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
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.demo.app.security.model.MyUser;

import java.util.Optional;

/**
 * Demo-only helper for UI permission checks.
 * <p>
 * Encapsulates the two recurring patterns:
 * <ul>
 *   <li>{@link #hasPermission(PermissionName)} — used to decide whether a UI
 *       element is visible or enabled (UX hint, not a security boundary).</li>
 *   <li>{@link #requirePermission(PermissionName)} — used inside event
 *       handlers immediately before any sensitive action runs (the actual
 *       server-side guard).</li>
 * </ul>
 * Hiding a button is convenience. Re-checking on click is the protection.
 */
public final class PermissionGuard {

  private PermissionGuard() {
  }

  /**
   * Returns {@code true} when the current subject has the given permission.
   * Use only for UX adaptation (visibility/enablement).
   */
  public static boolean hasPermission(PermissionName permission) {
    return currentUser()
        .map(user -> authorizationService().permissionsFor(user)
            .permissionNames()
            .contains(permission))
        .orElse(false);
  }

  /**
   * Throws when the current subject lacks the given permission. Call this
   * inside any sensitive click handler before performing the action.
   */
  public static void requirePermission(PermissionName permission) {
    if (!hasPermission(permission)) {
      throw new SecurityException("Missing permission: " + permission.value());
    }
  }

  private static AuthorizationService<MyUser> authorizationService() {
    return SecurityServiceResolver.authorizationService();
  }

  private static Optional<MyUser> currentUser() {
    return SubjectStores.subjectStore().currentSubject(MyUser.class);
  }
}
