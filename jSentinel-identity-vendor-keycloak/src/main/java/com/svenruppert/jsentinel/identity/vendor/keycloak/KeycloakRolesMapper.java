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
 * <code>{"roles":[...]}</code> objects, read only from the signed ID token.
 *
 * <p><strong>JS-SEC-042 (CWE-269):</strong> by default this mapper is
 * <em>client-scoped</em> — it emits the realm roles plus only <em>this
 * application's own</em> client roles (the client resolved from an explicit
 * {@code clientId}, else the token's {@code azp}, else a single-valued
 * {@code aud}). Flattening <em>every</em> client's roles un-namespaced would erase
 * Keycloak's client boundary: in a shared realm a user holding client role
 * {@code admin} on an unrelated client would satisfy {@code @RequiresRole("admin")}
 * here — cross-client privilege escalation. Use {@link #allClients()} to opt into
 * including every client's roles; those foreign-client roles are then
 * <em>namespaced</em> ({@code <client>:<role>}) so they cannot collide with this
 * app's roles. Absent / wrong-typed claim shapes yield no roles.
 */
public final class KeycloakRolesMapper implements ClaimsToRolesMapper {

  private final Optional<String> clientId;
  private final boolean allClients;

  /** Client-scoped to this app's own client, resolved from the token's {@code azp}/{@code aud}. */
  public KeycloakRolesMapper() {
    this(Optional.empty(), false);
  }

  /** Client-scoped to the explicitly-supplied own client id. */
  public KeycloakRolesMapper(String clientId) {
    this(Optional.of(clientId), false);
  }

  private KeycloakRolesMapper(Optional<String> clientId, boolean allClients) {
    this.clientId = clientId;
    this.allClients = allClients;
  }

  /**
   * Opt-in mapper that includes every client's roles from {@code resource_access};
   * foreign-client roles are namespaced {@code <client>:<role>} to avoid collisions.
   */
  public static KeycloakRolesMapper allClients() {
    return new KeycloakRolesMapper(Optional.empty(), true);
  }

  @Override
  public Set<RoleName> mapRoles(ValidatedIdToken idToken, Optional<UserInfoResponse> userInfo) {
    Map<String, Object> claims = idToken.jwt().claims();
    Set<RoleName> roles = new LinkedHashSet<>();
    // Realm roles are application-independent — always included, unqualified.
    rolesOf(claims.get("realm_access")).forEach(r -> roles.add(new RoleName(r)));
    if (claims.get("resource_access") instanceof Map<?, ?> resourceAccess) {
      if (allClients) {
        // opt-in: every client's roles, NAMESPACED so a foreign `admin` cannot collide.
        for (Map.Entry<?, ?> entry : resourceAccess.entrySet()) {
          String client = String.valueOf(entry.getKey());
          rolesOf(entry.getValue()).forEach(r -> roles.add(new RoleName(client + ":" + r)));
        }
      } else {
        // default: only THIS app's own client roles, unqualified — Keycloak's boundary preserved.
        ownClient(claims).ifPresent(client ->
            rolesOf(resourceAccess.get(client)).forEach(r -> roles.add(new RoleName(r))));
      }
    }
    return roles;
  }

  /** Resolves this app's own client id: explicit &rarr; {@code azp} &rarr; single-valued {@code aud}. */
  private Optional<String> ownClient(Map<String, Object> claims) {
    if (clientId.isPresent()) {
      return clientId;
    }
    if (claims.get("azp") instanceof String azp && !azp.isBlank()) {
      return Optional.of(azp);
    }
    Object aud = claims.get("aud");
    if (aud instanceof String s && !s.isBlank()) {
      return Optional.of(s);
    }
    if (aud instanceof List<?> list && list.size() == 1
        && list.get(0) instanceof String s && !s.isBlank()) {
      return Optional.of(s);
    }
    return Optional.empty();
  }

  /** Extracts the {@code roles} string list from a Keycloak {@code {"roles":[...]}} block. */
  private static List<String> rolesOf(Object accessBlock) {
    if (accessBlock instanceof Map<?, ?> map && map.get("roles") instanceof List<?> list) {
      return list.stream().filter(String.class::isInstance).map(String.class::cast).toList();
    }
    return List.of();
  }
}
