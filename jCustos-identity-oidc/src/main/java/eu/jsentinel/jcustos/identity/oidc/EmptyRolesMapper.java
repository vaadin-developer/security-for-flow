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
package eu.jsentinel.jcustos.identity.oidc;

import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.oidc.api.ClaimsToRolesMapper;
import eu.jsentinel.jcustos.oidc.api.UserInfoResponse;
import eu.jsentinel.jcustos.oidc.api.ValidatedIdToken;

import java.util.Optional;
import java.util.Set;

/**
 * The spec-clean default: no roles (V00.78). Vendor role mappings
 * (Keycloak {@code realm_access.roles}, Entra {@code wids}, …) are V00.79.
 */
public final class EmptyRolesMapper implements ClaimsToRolesMapper {

  public static final EmptyRolesMapper INSTANCE = new EmptyRolesMapper();

  public EmptyRolesMapper() {
  }

  @Override
  public Set<RoleName> mapRoles(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo) {
    return Set.of();
  }
}
