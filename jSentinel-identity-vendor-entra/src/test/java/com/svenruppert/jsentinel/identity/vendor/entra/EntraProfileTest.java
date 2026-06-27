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
package com.svenruppert.jsentinel.identity.vendor.entra;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.svenruppert.jsentinel.authorization.api.tenant.TenantId;
import com.svenruppert.jsentinel.jwt.api.JoseHeader;
import com.svenruppert.jsentinel.jwt.api.ValidatedJwt;
import com.svenruppert.jsentinel.oidc.api.ValidatedIdToken;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("EntraProfile — roles from roles/wids/groups + tenant from tid")
class EntraProfileTest {

  private static ValidatedIdToken idToken(Map<String, Object> claims) {
    return new ValidatedIdToken(new ValidatedJwt("c",
        new JoseHeader("RS256", Optional.empty(), Optional.empty()), claims, Instant.now()),
        Optional.empty(), Optional.empty(), Optional.empty(), List.of(), Optional.empty(),
        Optional.empty());
  }

  @Test
  @DisplayName("combines roles, wids and groups into RoleNames")
  void combinesRoleSources() {
    Set<RoleName> roles = EntraProfile.INSTANCE.rolesMapper().orElseThrow().mapRoles(
        idToken(Map.of("roles", List.of("App.Admin"), "wids", List.of("wid-1"),
            "groups", List.of("grp-a"))), Optional.empty());
    assertEquals(Set.of(new RoleName("App.Admin"), new RoleName("wid-1"), new RoleName("grp-a")), roles);
  }

  @Test
  @DisplayName("maps the tid claim to the tenant")
  void mapsTid() {
    Optional<TenantId> tenant = EntraProfile.INSTANCE.tenantMapper().orElseThrow().mapTenant(
        idToken(Map.of("tid", "contoso-tenant")), Optional.empty());
    assertEquals(Optional.of(TenantId.of("contoso-tenant")), tenant);
  }

  @Test
  @DisplayName("profile id is entra")
  void id() {
    assertEquals("entra", EntraProfile.INSTANCE.id());
  }
}
