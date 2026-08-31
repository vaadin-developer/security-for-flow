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
package eu.jsentinel.jcustos.oidc.api;

import eu.jsentinel.jcustos.authorization.api.roles.RoleName;

import java.util.Optional;
import java.util.Set;

/**
 * Maps OIDC claims to {@link RoleName}s (V00.78). V00.78 ships only the spec-clean
 * default (no roles — {@code EmptyRolesMapper}); vendor mappers (Keycloak
 * {@code realm_access.roles}, Entra {@code wids}, Auth0 namespace claims) are a
 * V00.79 hardening concern.
 *
 * @since 00.78.00
 */
public interface ClaimsToRolesMapper {
  Set<RoleName> mapRoles(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo);
}
