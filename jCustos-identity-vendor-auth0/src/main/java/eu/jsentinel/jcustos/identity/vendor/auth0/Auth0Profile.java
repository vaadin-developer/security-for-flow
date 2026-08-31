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
package eu.jsentinel.jcustos.identity.vendor.auth0;

import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.oidc.api.ClaimsToPermissionsMapper;
import eu.jsentinel.jcustos.oidc.api.ClaimsToRolesMapper;
import eu.jsentinel.jcustos.oidc.api.VendorProfile;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * The Auth0 vendor profile (V00.79). Auth0 cannot emit bare top-level custom
 * claims, so roles are delivered under a configurable namespace
 * (e.g. {@code https://my-app.example/roles}); Auth0 RBAC permissions arrive in the
 * {@code permissions} claim. Construct with the app namespace, or use
 * {@link #INSTANCE} with the jCustos default namespace.
 */
public final class Auth0Profile implements VendorProfile {

  /** Default roles namespace when none is configured. */
  public static final String DEFAULT_NAMESPACE = "https://jsentinel.eu/roles";

  /** Profile with the default namespace. */
  public static final Auth0Profile INSTANCE = new Auth0Profile(DEFAULT_NAMESPACE);

  private final String rolesNamespace;

  public Auth0Profile(String rolesNamespace) {
    this.rolesNamespace = Objects.requireNonNull(rolesNamespace, "rolesNamespace");
  }

  @Override
  public String id() {
    return "auth0";
  }

  @Override
  public Optional<ClaimsToRolesMapper> rolesMapper() {
    String ns = rolesNamespace;
    return Optional.of((idToken, userInfo) -> {
      Set<RoleName> roles = new LinkedHashSet<>();
      if (idToken.jwt().claims().get(ns) instanceof List<?> list) {
        for (Object o : list) {
          if (o instanceof String s) {
            roles.add(new RoleName(s));
          }
        }
      }
      return roles;
    });
  }

  @Override
  public Optional<ClaimsToPermissionsMapper> permissionsMapper() {
    return Optional.of((idToken, userInfo) -> {
      Set<PermissionName> perms = new LinkedHashSet<>();
      if (idToken.jwt().claims().get("permissions") instanceof List<?> list) {
        for (Object o : list) {
          if (o instanceof String s) {
            perms.add(new PermissionName(s));
          }
        }
      }
      return perms;
    });
  }
}
