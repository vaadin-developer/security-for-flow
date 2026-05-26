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
package com.svenruppert.vaadin.security.policy.api;

import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SubjectPredicatesTest {

  private static PolicyContext anonymousCtx() {
    return new PolicyContext(
        new AccessContext(Optional.empty(), "rest-endpoint", "/x", "read", Map.of()),
        "test.policy");
  }

  private static PolicyContext ctxWith(Set<RoleName> roles, Set<PermissionName> perms) {
    SecuritySubject subject = new SecuritySubject("u-1", "u-1", roles, perms);
    return new PolicyContext(
        new AccessContext(Optional.of(subject), "rest-endpoint", "/x", "read", Map.of()),
        "test.policy");
  }

  @Test
  @DisplayName("hasRole matches when subject holds the role")
  void hasRoleMatches() {
    PolicyContext ctx = ctxWith(Set.of(new RoleName("ADMIN")), Set.of());
    assertTrue(SubjectPredicates.hasRole("ADMIN").test(ctx));
  }

  @Test
  @DisplayName("hasRole does not match when subject lacks the role")
  void hasRoleDoesNotMatch() {
    PolicyContext ctx = ctxWith(Set.of(new RoleName("USER")), Set.of());
    assertFalse(SubjectPredicates.hasRole("ADMIN").test(ctx));
  }

  @Test
  @DisplayName("hasRole returns false when no subject is bound")
  void hasRoleAnonymous() {
    assertFalse(SubjectPredicates.hasRole("ADMIN").test(anonymousCtx()));
  }

  @Test
  @DisplayName("hasRole rejects null and blank")
  void hasRoleRejectsBlank() {
    assertThrows(NullPointerException.class, () -> SubjectPredicates.hasRole(null));
    assertThrows(IllegalArgumentException.class, () -> SubjectPredicates.hasRole(""));
    assertThrows(IllegalArgumentException.class, () -> SubjectPredicates.hasRole("   "));
  }

  @Test
  @DisplayName("hasAnyRole matches when subject holds any listed role")
  void hasAnyRoleMatchesOne() {
    PolicyContext ctx = ctxWith(Set.of(new RoleName("EDITOR")), Set.of());
    assertTrue(SubjectPredicates.hasAnyRole("ADMIN", "EDITOR", "VIEWER").test(ctx));
  }

  @Test
  @DisplayName("hasAnyRole does not match when subject holds none of the listed roles")
  void hasAnyRoleNoneMatches() {
    PolicyContext ctx = ctxWith(Set.of(new RoleName("GUEST")), Set.of());
    assertFalse(SubjectPredicates.hasAnyRole("ADMIN", "EDITOR").test(ctx));
  }

  @Test
  @DisplayName("hasAnyRole returns false when no subject is bound")
  void hasAnyRoleAnonymous() {
    assertFalse(SubjectPredicates.hasAnyRole("ADMIN", "EDITOR").test(anonymousCtx()));
  }

  @Test
  @DisplayName("hasAnyRole rejects empty varargs")
  void hasAnyRoleRejectsEmpty() {
    assertThrows(IllegalArgumentException.class, SubjectPredicates::hasAnyRole);
  }

  @Test
  @DisplayName("hasAnyRole rejects null varargs")
  void hasAnyRoleRejectsNull() {
    assertThrows(NullPointerException.class,
        () -> SubjectPredicates.hasAnyRole((String[]) null));
  }

  @Test
  @DisplayName("hasPermission matches when subject holds the permission")
  void hasPermissionMatches() {
    PolicyContext ctx = ctxWith(Set.of(), Set.of(new PermissionName("document:write")));
    assertTrue(SubjectPredicates.hasPermission("document:write").test(ctx));
  }

  @Test
  @DisplayName("hasPermission does not match when subject lacks the permission")
  void hasPermissionDoesNotMatch() {
    PolicyContext ctx = ctxWith(Set.of(), Set.of(new PermissionName("document:read")));
    assertFalse(SubjectPredicates.hasPermission("document:write").test(ctx));
  }

  @Test
  @DisplayName("hasPermission returns false when no subject is bound")
  void hasPermissionAnonymous() {
    assertFalse(SubjectPredicates.hasPermission("document:write").test(anonymousCtx()));
  }

  @Test
  @DisplayName("hasPermission rejects null and blank")
  void hasPermissionRejectsBlank() {
    assertThrows(NullPointerException.class, () -> SubjectPredicates.hasPermission(null));
    assertThrows(IllegalArgumentException.class, () -> SubjectPredicates.hasPermission(""));
  }

  @Test
  @DisplayName("isAnonymous matches when no subject is bound")
  void isAnonymousMatches() {
    assertTrue(SubjectPredicates.isAnonymous().test(anonymousCtx()));
  }

  @Test
  @DisplayName("isAnonymous does not match when a subject is bound")
  void isAnonymousDoesNotMatchAuthenticated() {
    PolicyContext ctx = ctxWith(Set.of(new RoleName("USER")), Set.of());
    assertFalse(SubjectPredicates.isAnonymous().test(ctx));
  }
}
