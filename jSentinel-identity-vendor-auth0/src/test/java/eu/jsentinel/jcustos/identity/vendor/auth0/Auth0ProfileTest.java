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

import static org.junit.jupiter.api.Assertions.assertEquals;

import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.jwt.api.JoseHeader;
import eu.jsentinel.jcustos.jwt.api.ValidatedJwt;
import eu.jsentinel.jcustos.oidc.api.ValidatedIdToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("Auth0Profile — namespaced roles + RBAC permissions")
class Auth0ProfileTest {

  private static ValidatedIdToken idToken(Map<String, Object> claims) {
    return new ValidatedIdToken(new ValidatedJwt("c",
        new JoseHeader("RS256", Optional.empty(), Optional.empty()), claims, Instant.now()),
        Optional.empty(), Optional.empty(), Optional.empty(), List.of(), Optional.empty(),
        Optional.empty());
  }

  @Test
  @DisplayName("extracts roles from the configured namespace and permissions from the permissions claim")
  void extractsRolesAndPermissions() {
    Auth0Profile profile = new Auth0Profile("https://app.example/roles");
    ValidatedIdToken token = idToken(Map.of(
        "https://app.example/roles", List.of("admin", "editor"),
        "permissions", List.of("doc:read", "doc:write")));
    assertEquals(Set.of(new RoleName("admin"), new RoleName("editor")),
        profile.rolesMapper().orElseThrow().mapRoles(token, Optional.empty()));
    assertEquals(Set.of(new PermissionName("doc:read"), new PermissionName("doc:write")),
        profile.permissionsMapper().orElseThrow().mapPermissions(token, Optional.empty()));
  }

  @Test
  @DisplayName("the default INSTANCE uses the jSentinel default namespace")
  void defaultNamespace() {
    Set<RoleName> roles = Auth0Profile.INSTANCE.rolesMapper().orElseThrow().mapRoles(
        idToken(Map.of(Auth0Profile.DEFAULT_NAMESPACE, List.of("user"))), Optional.empty());
    assertEquals(Set.of(new RoleName("user")), roles);
    assertEquals("auth0", Auth0Profile.INSTANCE.id());
  }
}
