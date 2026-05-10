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
package com.svenruppert.vaadin.security.action;

import com.svenruppert.vaadin.security.authorization.api.AccessDeniedException;

/**
 * SPI for fine-grained action checks.
 * <p>
 * Two complementary entry points map to the canonical Vaadin pattern:
 * <ul>
 *   <li>{@link #isAllowed(Object, ActionPermission)} drives UI state
 *       (visibility, enablement, menu rendering).</li>
 *   <li>{@link #requireAllowed(Object, ActionPermission)} is the
 *       authoritative server-side guard called immediately before a
 *       mutating or sensitive action runs.</li>
 * </ul>
 *
 * <p>The second check is mandatory — UI-level visibility is convenience,
 * never the actual access control.
 *
 * @param <U> the application's subject type
 */
public interface ActionAuthorizationService<U> {

  /**
   * @return {@code true} if {@code subject} may execute {@code permission}
   */
  boolean isAllowed(U subject, ActionPermission permission);

  /**
   * Throws {@link AccessDeniedException} if the subject is not allowed.
   * Implementations should additionally emit a
   * {@link com.svenruppert.vaadin.security.audit.SecurityAuditEventType#ACTION_DENIED}
   * audit event in this case.
   */
  default void requireAllowed(U subject, ActionPermission permission) {
    if (!isAllowed(subject, permission)) {
      throw new AccessDeniedException(
          "Missing action permission: " + (permission == null ? "<null>" : permission.name()));
    }
  }
}
