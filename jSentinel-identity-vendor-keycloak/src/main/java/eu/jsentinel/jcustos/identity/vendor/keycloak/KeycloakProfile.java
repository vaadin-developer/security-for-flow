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
package eu.jsentinel.jcustos.identity.vendor.keycloak;

import eu.jsentinel.jcustos.oidc.api.ClaimsToRolesMapper;
import eu.jsentinel.jcustos.oidc.api.VendorProfile;

import java.util.Optional;

/**
 * The Keycloak vendor profile (V00.79): wires the {@link KeycloakRolesMapper} so a
 * consumer can write {@code .oidc(o -> o.vendor(KeycloakProfile.INSTANCE))} and get
 * Keycloak realm + client roles out of the box. Keycloak follows the OIDC spec for
 * the rest (subject, tenant), so only the roles mapper is overridden.
 *
 * @see <a href="https://www.keycloak.org/docs/latest/server_admin/#_role_scope_mappings">Keycloak roles</a>
 */
public final class KeycloakProfile implements VendorProfile {

  /** The shared, stateless Keycloak profile instance. */
  public static final KeycloakProfile INSTANCE = new KeycloakProfile();

  public KeycloakProfile() {
  }

  @Override
  public String id() {
    return "keycloak";
  }

  @Override
  public Optional<ClaimsToRolesMapper> rolesMapper() {
    return Optional.of(new KeycloakRolesMapper());
  }
}
