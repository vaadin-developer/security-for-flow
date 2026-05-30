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
package com.svenruppert.vaadin.security.authorization.api.roles;

import com.svenruppert.vaadin.security.authorization.api.tenant.TenantId;
import com.svenruppert.vaadin.security.logout.SubjectId;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("StoreBackedRoleAuthorizationService")
class StoreBackedRoleAuthorizationServiceTest {

  private static final RoleName ADMIN = new RoleName("ADMIN");
  private static final RoleName EDITOR = new RoleName("EDITOR");

  record DemoUser(String username, String tenant) {}

  private static final Function<DemoUser, SubjectId> SUBJECT_RESOLVER =
      u -> new SubjectId(u.username());
  private static final Function<DemoUser, TenantId> TENANT_RESOLVER =
      u -> new TenantId(u.tenant());

  @Test
  @DisplayName("rolesFor reads from the store using the resolved key")
  void rolesForReadsStore() {
    InMemoryRoleAssignmentStore store = new InMemoryRoleAssignmentStore();
    store.assignRole(
        new RoleAssignmentKey(new TenantId("acme"), new SubjectId("alice")),
        ADMIN);
    store.assignRole(
        new RoleAssignmentKey(new TenantId("acme"), new SubjectId("alice")),
        EDITOR);

    StoreBackedRoleAuthorizationService<DemoUser> service =
        new StoreBackedRoleAuthorizationService<>(store, SUBJECT_RESOLVER, TENANT_RESOLVER);

    Set<RoleName> roles = new HashSet<>(service
        .rolesFor(new DemoUser("alice", "acme"))
        .roleNames());
    assertEquals(Set.of(ADMIN, EDITOR), roles);
  }

  @Test
  @DisplayName("rolesFor on an unmapped subject returns the empty set")
  void unmappedSubjectEmpty() {
    InMemoryRoleAssignmentStore store = new InMemoryRoleAssignmentStore();
    StoreBackedRoleAuthorizationService<DemoUser> service =
        new StoreBackedRoleAuthorizationService<>(store, SUBJECT_RESOLVER, TENANT_RESOLVER);

    assertTrue(service.rolesFor(new DemoUser("ghost", "acme")).roleNames().isEmpty());
  }

  @Test
  @DisplayName("single-tenant constructor uses TenantId.DEFAULT for every lookup")
  void singleTenantConstructor() {
    InMemoryRoleAssignmentStore store = new InMemoryRoleAssignmentStore();
    store.assignRole(
        new RoleAssignmentKey(TenantId.DEFAULT, new SubjectId("alice")),
        ADMIN);

    StoreBackedRoleAuthorizationService<DemoUser> service =
        new StoreBackedRoleAuthorizationService<>(store, SUBJECT_RESOLVER);

    Set<RoleName> roles = new HashSet<>(
        service.rolesFor(new DemoUser("alice", "ignored")).roleNames());
    assertEquals(Set.of(ADMIN), roles);
  }

  @Test
  @DisplayName("tenant resolver returning null is normalised to DEFAULT")
  void tenantResolverNullBecomesDefault() {
    InMemoryRoleAssignmentStore store = new InMemoryRoleAssignmentStore();
    store.assignRole(
        new RoleAssignmentKey(TenantId.DEFAULT, new SubjectId("alice")),
        ADMIN);

    StoreBackedRoleAuthorizationService<DemoUser> service =
        new StoreBackedRoleAuthorizationService<>(store, SUBJECT_RESOLVER, u -> null);

    Set<RoleName> roles = new HashSet<>(
        service.rolesFor(new DemoUser("alice", "ignored")).roleNames());
    assertEquals(Set.of(ADMIN), roles);
  }

  @Test
  @DisplayName("snapshot semantics — store mutations after rolesFor don't leak into the returned HasRoles")
  void snapshotSemantics() {
    InMemoryRoleAssignmentStore store = new InMemoryRoleAssignmentStore();
    store.assignRole(
        new RoleAssignmentKey(TenantId.DEFAULT, new SubjectId("alice")),
        ADMIN);

    StoreBackedRoleAuthorizationService<DemoUser> service =
        new StoreBackedRoleAuthorizationService<>(store, SUBJECT_RESOLVER);

    var snapshot = service.rolesFor(new DemoUser("alice", "ignored"));
    store.assignRole(
        new RoleAssignmentKey(TenantId.DEFAULT, new SubjectId("alice")),
        EDITOR);

    Set<RoleName> roles = new HashSet<>(snapshot.roleNames());
    assertEquals(Set.of(ADMIN), roles,
        "the HasRoles returned by rolesFor is a snapshot");
  }

  @Test
  @DisplayName("null arguments / null subjectIdResolver result are rejected")
  void rejectNulls() {
    InMemoryRoleAssignmentStore store = new InMemoryRoleAssignmentStore();
    assertThrows(NullPointerException.class,
        () -> new StoreBackedRoleAuthorizationService<>(null, SUBJECT_RESOLVER));
    assertThrows(NullPointerException.class,
        () -> new StoreBackedRoleAuthorizationService<DemoUser>(store, null));
    assertThrows(NullPointerException.class,
        () -> new StoreBackedRoleAuthorizationService<>(store, SUBJECT_RESOLVER, null));

    StoreBackedRoleAuthorizationService<DemoUser> service =
        new StoreBackedRoleAuthorizationService<>(store, SUBJECT_RESOLVER);
    assertThrows(NullPointerException.class, () -> service.rolesFor(null));

    StoreBackedRoleAuthorizationService<DemoUser> brokenResolver =
        new StoreBackedRoleAuthorizationService<>(store, u -> null);
    assertThrows(NullPointerException.class,
        () -> brokenResolver.rolesFor(new DemoUser("alice", "x")));
  }
}
