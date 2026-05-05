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
package com.svenruppert.vaadin.security.authorization.api.roles;

import java.util.Collection;

/**
 * Generic role matching helper.
 */
public final class RoleMatcher {

  private RoleMatcher() {
  }

  /**
   * Checks whether any required role is present in the granted set.
   *
   * @param granted  granted roles
   * @param required required roles
   * @return true if at least one required role is granted
   */
  public static boolean containsAny(Collection<RoleName> granted, Collection<RoleName> required) {
    return required.stream().anyMatch(granted::contains);
  }
}
