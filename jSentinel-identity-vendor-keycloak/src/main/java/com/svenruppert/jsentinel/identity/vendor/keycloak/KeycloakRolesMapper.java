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
package com.svenruppert.jsentinel.identity.vendor.keycloak;

import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.svenruppert.jsentinel.oidc.api.ClaimsToRolesMapper;
import com.svenruppert.jsentinel.oidc.api.UserInfoResponse;
import com.svenruppert.jsentinel.oidc.api.ValidatedIdToken;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Maps Keycloak's role claims to {@link RoleName}s (V00.79). Keycloak puts realm
 * roles in {@code realm_access.roles} and per-client roles in
 * {@code resource_access.<client-id>.roles}; both are nested
 * <code>{"roles":[...]}</code> objects. This mapper extracts the realm roles and
 * — by default — the roles of every client in {@code resource_access}, reading
 * only the signed ID-token claims (never UserInfo, which Keycloak does not use for
 * roles). Vendor claim shapes that are absent or of the wrong type yield no roles.
 */
public final class KeycloakRolesMapper implements ClaimsToRolesMapper {

  public KeycloakRolesMapper() {
  }

  @Override
  public Set<RoleName> mapRoles(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo) {
    Map<String, Object> claims = idToken.jwt().claims();
    Set<RoleName> roles = new LinkedHashSet<>();
    rolesOf(claims.get("realm_access")).forEach(r -> roles.add(new RoleName(r)));
    if (claims.get("resource_access") instanceof Map<?, ?> resourceAccess) {
      for (Object client : resourceAccess.values()) {
        rolesOf(client).forEach(r -> roles.add(new RoleName(r)));
      }
    }
    return roles;
  }

  /** Extracts the {@code roles} string list from a Keycloak {@code {"roles":[...]}} block. */
  private static List<String> rolesOf(Object accessBlock) {
    if (accessBlock instanceof Map<?, ?> map && map.get("roles") instanceof List<?> list) {
      return list.stream().filter(String.class::isInstance).map(String.class::cast).toList();
    }
    return List.of();
  }
}
