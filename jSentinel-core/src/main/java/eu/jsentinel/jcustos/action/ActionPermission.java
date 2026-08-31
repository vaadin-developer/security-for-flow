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
package eu.jsentinel.jcustos.action;

import java.util.Objects;

/**
 * Stable, typed identifier for a fine-grained business action.
 * <p>
 * Use {@link ActionPermission} for action-level checks
 * ({@code USER_ADMINISTRATION_DELETE}, {@code REPORT_EXPORT}) and reserve
 * {@code eu.jsentinel.jcustos.authorization.api.permissions.PermissionName}
 * for route- / view-level permission gates. The two are intentionally
 * separate types so the call sites read differently and so applications
 * can adopt {@link ActionPermission} without depending on the still
 * experimental permission API.
 *
 * @param name non-blank, stable name of the action
 */
public record ActionPermission(String name) {

  /** Defensive constructor — rejects null and blank names. */
  public ActionPermission {
    Objects.requireNonNull(name, "name must not be null");
    if (name.isBlank()) {
      throw new IllegalArgumentException("Action permission name must not be blank");
    }
  }
}
