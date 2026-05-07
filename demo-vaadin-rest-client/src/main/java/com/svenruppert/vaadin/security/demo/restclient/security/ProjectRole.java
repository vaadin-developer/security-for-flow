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
package com.svenruppert.vaadin.security.demo.restclient.security;

import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;

/**
 * Demo-side role enum used by the project-specific
 * {@link VisibleForRoles} annotation. Maps to the backend's
 * {@code ROLE_*} role names.
 */
public enum ProjectRole {
  ADMIN,
  EDITOR,
  VIEWER;

  public RoleName roleName() {
    return new RoleName("ROLE_" + name());
  }
}
