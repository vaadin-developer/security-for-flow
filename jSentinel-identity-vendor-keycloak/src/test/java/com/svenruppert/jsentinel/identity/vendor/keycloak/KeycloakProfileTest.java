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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import com.svenruppert.jsentinel.identity.oidc.DefaultIdTokenValidator;
import com.svenruppert.jsentinel.jwt.api.AlgorithmProfile;
import com.svenruppert.jsentinel.jwt.api.ClaimExpectations;
import com.svenruppert.jsentinel.jwt.api.ClockSkewPolicy;
import com.svenruppert.jsentinel.jwt.api.JwksClient;
import com.svenruppert.jsentinel.jwt.api.JwksRefreshResult;
import com.svenruppert.jsentinel.jwt.api.JwsAlgorithm;
import com.svenruppert.jsentinel.jwt.impl.NimbusJwtValidator;
import com.svenruppert.jsentinel.oidc.api.IdTokenExpectations;
import com.svenruppert.jsentinel.oidc.api.ValidatedIdToken;
import com.svenruppert.jsentinel.test.oidc.MockClock;
import com.svenruppert.jsentinel.test.oidc.StubIdentityProvider;

import java.security.PublicKey;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

@DisplayName("KeycloakProfile — realm + client roles from a real signed ID token (no mocks)")
class KeycloakProfileTest {

  private StubIdentityProvider idp;
  private final MockClock clock = MockClock.fixed();

  @BeforeEach
  void start() {
    System.setProperty("jsentinel.dev", "true");
    idp = StubIdentityProvider.start("rp", clock).withIdTokenClaims(Map.of(
        "sub", "alice",
        "realm_access", Map.of("roles", java.util.List.of("admin", "user")),
        "resource_access", Map.of("my-client", Map.of("roles", java.util.List.of("editor")))));
  }

  @AfterEach
  void stop() {
    idp.close();
    System.clearProperty("jsentinel.dev");
  }

  private ValidatedIdToken validate(String compact) {
    PublicKey key;
    try {
      key = idp.publicSigningKey().toPublicKey();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    JwksClient keys = new JwksClient() {
      @Override public Optional<PublicKey> findKey(String kid, JwsAlgorithm alg) {
        return Optional.of(key);
      }

      @Override public JwksRefreshResult refreshOnce() {
        return new JwksRefreshResult(1, clock.get(), Duration.ofMinutes(5), Optional.empty());
      }
    };
    NimbusJwtValidator jwt = new NimbusJwtValidator(AlgorithmProfile.STRICT_MODERN.toAllowList(), keys,
        new ClaimExpectations(Optional.of(idp.issuer()), Set.of("rp"),
            true, false, false, false, ClockSkewPolicy.DEFAULT, Optional.empty()), clock);
    return new DefaultIdTokenValidator(jwt, clock)
        .validate(compact, IdTokenExpectations.of(idp.issuer(), "rp", Optional.empty()))
        .toOptional().orElseThrow();
  }

  @Test
  @DisplayName("realm_access + resource_access roles are extracted into RoleNames")
  void extractsRealmAndClientRoles() {
    // the app's own client is "rp" (the token audience), so its client roles live under
    // resource_access.rp — the client-scoped default (JS-SEC-042) picks them up.
    String idToken = idp.signIdToken(Map.of(
        "iss", idp.issuer(), "sub", "alice", "aud", "rp",
        "iat", clock.get().getEpochSecond(), "exp", clock.get().plusSeconds(300).getEpochSecond(),
        "realm_access", Map.of("roles", java.util.List.of("admin", "user")),
        "resource_access", Map.of("rp", Map.of("roles", java.util.List.of("editor")))));
    ValidatedIdToken vit = validate(idToken);

    Set<RoleName> roles = KeycloakProfile.INSTANCE.rolesMapper().orElseThrow()
        .mapRoles(vit, Optional.empty());
    assertEquals(Set.of(new RoleName("admin"), new RoleName("user"), new RoleName("editor")), roles);
  }

  @Test
  @DisplayName("JS-SEC-042: a foreign client's role is NOT granted un-namespaced (client-scoped default)")
  void foreignClientRoleNotGrantedByDefault() {
    // mallory holds `admin` on the unrelated `reporting-tool` client and only `viewer` on our
    // own `rp` client. The default client-scoped mapper must not grant a bare `admin`.
    String idToken = idp.signIdToken(Map.of(
        "iss", idp.issuer(), "sub", "mallory", "aud", "rp",
        "iat", clock.get().getEpochSecond(), "exp", clock.get().plusSeconds(300).getEpochSecond(),
        "resource_access", Map.of(
            "rp", Map.of("roles", java.util.List.of("viewer")),
            "reporting-tool", Map.of("roles", java.util.List.of("admin")))));
    Set<RoleName> roles = new KeycloakRolesMapper().mapRoles(validate(idToken), Optional.empty());
    assertTrue(roles.contains(new RoleName("viewer")), "own client's role is granted");
    assertFalse(roles.contains(new RoleName("admin")),
        "a foreign client's admin must NOT collide with this app's admin");
  }

  @Test
  @DisplayName("JS-SEC-042: allClients() includes every client's roles, namespaced")
  void allClientsIncludesNamespacedRoles() {
    String idToken = idp.signIdToken(Map.of(
        "iss", idp.issuer(), "sub", "mallory", "aud", "rp",
        "iat", clock.get().getEpochSecond(), "exp", clock.get().plusSeconds(300).getEpochSecond(),
        "resource_access", Map.of(
            "rp", Map.of("roles", java.util.List.of("viewer")),
            "reporting-tool", Map.of("roles", java.util.List.of("admin")))));
    Set<RoleName> roles = KeycloakRolesMapper.allClients().mapRoles(validate(idToken), Optional.empty());
    assertTrue(roles.contains(new RoleName("rp:viewer")));
    assertTrue(roles.contains(new RoleName("reporting-tool:admin")));
    assertFalse(roles.contains(new RoleName("admin")), "foreign roles are namespaced, never bare");
  }

  @Test
  @DisplayName("a token without keycloak role claims yields no roles")
  void noRoleClaimsYieldsEmpty() {
    String idToken = idp.signIdToken(Map.of(
        "iss", idp.issuer(), "sub", "bob", "aud", "rp",
        "iat", clock.get().getEpochSecond(), "exp", clock.get().plusSeconds(300).getEpochSecond()));
    Set<RoleName> roles = new KeycloakRolesMapper().mapRoles(validate(idToken), Optional.empty());
    assertTrue(roles.isEmpty());
  }

  @Test
  @DisplayName("profile id is keycloak")
  void profileId() {
    assertEquals("keycloak", KeycloakProfile.INSTANCE.id());
  }
}
