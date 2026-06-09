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
package com.svenruppert.jsentinel.authorization.api.operations;

import com.svenruppert.jsentinel.authorization.api.JSentinelSubject;
import com.svenruppert.jsentinel.authorization.api.permissions.PermissionName;
import com.svenruppert.jsentinel.authorization.api.roles.RoleName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;

@DisplayName("SecuredOperationRegistry + OperationVisibilityService")
class SecuredOperationRegistryTest {

  private final PermissionName read = new PermissionName("doc:read");
  private final PermissionName del = new PermissionName("doc:delete");

  private SecuredOperationDescriptor op(String id, Set<PermissionName> perms) {
    return new SecuredOperationDescriptor(
        id, "Op " + id, "", "rest-endpoint", "/op/" + id, "do",
        Set.of(), perms, Map.of());
  }

  private SecuredOperationDescriptor opWithRole(String id, RoleName r) {
    return new SecuredOperationDescriptor(
        id, "Op " + id, "", "rest-endpoint", "/op/" + id, "do",
        Set.of(r), Set.of(), Map.of());
  }

  @Test
  @DisplayName("register/findById round-trips")
  void registerFind() {
    SecuredOperationRegistry registry = new SecuredOperationRegistry();
    registry.register(op("read", Set.of(read)));
    registry.register(op("delete", Set.of(del)));
    assertEquals(2, registry.all().size());
    assertTrue(registry.findById("read").isPresent());
    assertTrue(registry.findById("nope").isEmpty());
  }

  @Test
  @DisplayName("duplicate registration is rejected")
  void duplicate() {
    SecuredOperationRegistry registry = new SecuredOperationRegistry();
    registry.register(op("read", Set.of(read)));
    assertThrows(IllegalStateException.class,
        () -> registry.register(op("read", Set.of(read))));
  }

  @Test
  @DisplayName("visibility filters by required permissions")
  void visibility() {
    SecuredOperationRegistry registry = new SecuredOperationRegistry();
    registry.register(op("read", Set.of(read)));
    registry.register(op("delete", Set.of(del)));
    OperationVisibilityService service = new OperationVisibilityService(registry);

    JSentinelSubject viewer = new JSentinelSubject("u", "Viewer",
        Set.of(new RoleName("ROLE_VIEWER")), Set.of(read));
    List<SecuredOperationDescriptor> visible = service.visibleFor(viewer);
    assertEquals(1, visible.size());
    assertEquals("read", visible.get(0).id());
  }

  @Test
  @DisplayName("visibility for a null subject is empty")
  void nullSubject() {
    SecuredOperationRegistry registry = new SecuredOperationRegistry();
    registry.register(op("read", Set.of(read)));
    OperationVisibilityService service = new OperationVisibilityService(registry);
    assertTrue(service.visibleFor(null).isEmpty());
  }

  @Test
  @DisplayName("operation without role/permission gates passes for any subject")
  void authenticatedOnlyOperation() {
    SecuredOperationRegistry registry = new SecuredOperationRegistry();
    registry.register(op("ping", Set.of()));
    OperationVisibilityService service = new OperationVisibilityService(registry);

    JSentinelSubject anon = new JSentinelSubject("u", "Any", Set.of(), Set.of());
    assertEquals(1, service.visibleFor(anon).size());
  }

  @Test
  @DisplayName("isEmpty true on a fresh registry, false after register")
  void registryIsEmpty() {
    SecuredOperationRegistry registry = new SecuredOperationRegistry();
    assertTrue(registry.isEmpty());
    registry.register(op("read", Set.of(read)));
    assertFalse(registry.isEmpty());
  }

  @Test
  @DisplayName("snapshot reflects registered descriptors and is independent of further registrations")
  void snapshotIsIndependent() {
    SecuredOperationRegistry registry = new SecuredOperationRegistry();
    registry.register(op("read", Set.of(read)));
    Map<String, SecuredOperationDescriptor> snap1 = registry.snapshot();
    assertEquals(1, snap1.size());
    assertTrue(snap1.containsKey("read"));

    registry.register(op("delete", Set.of(del)));
    assertEquals(1, snap1.size(), "earlier snapshot must not see later registrations");
    assertEquals(2, registry.snapshot().size());
  }

  @Test
  @DisplayName("snapshot is unmodifiable")
  void snapshotIsUnmodifiable() {
    SecuredOperationRegistry registry = new SecuredOperationRegistry();
    registry.register(op("read", Set.of(read)));
    Map<String, SecuredOperationDescriptor> snap = registry.snapshot();
    assertThrows(UnsupportedOperationException.class,
        () -> snap.put("delete", op("delete", Set.of(del))));
  }

  @Test
  @DisplayName("operation requiring a role the subject lacks is filtered out")
  void requiredRoleMissingFiltersOut() {
    SecuredOperationRegistry registry = new SecuredOperationRegistry();
    registry.register(opWithRole("admin-only", new RoleName("ROLE_ADMIN")));
    OperationVisibilityService service = new OperationVisibilityService(registry);

    JSentinelSubject viewer = new JSentinelSubject("u", "Viewer",
        Set.of(new RoleName("ROLE_VIEWER")), Set.of());
    assertTrue(service.visibleFor(viewer).isEmpty());
  }

  @Test
  @DisplayName("operation requiring a role the subject has is visible")
  void requiredRolePresentVisible() {
    SecuredOperationRegistry registry = new SecuredOperationRegistry();
    RoleName admin = new RoleName("ROLE_ADMIN");
    registry.register(opWithRole("admin-only", admin));
    OperationVisibilityService service = new OperationVisibilityService(registry);

    JSentinelSubject adminSubject = new JSentinelSubject("u", "Admin",
        Set.of(admin), Set.of());
    assertEquals(1, service.visibleFor(adminSubject).size());
  }

  @Test
  @DisplayName("isAuthenticatedOnly is true only when both required sets are empty")
  void isAuthenticatedOnlySemantics() {
    PermissionName p = new PermissionName("doc:read");
    RoleName r = new RoleName("ROLE_X");

    SecuredOperationDescriptor noGates = new SecuredOperationDescriptor(
        "a", "A", "", "rest", "/a", "do", Set.of(), Set.of(), Map.of());
    SecuredOperationDescriptor onlyRole = new SecuredOperationDescriptor(
        "b", "B", "", "rest", "/b", "do", Set.of(r), Set.of(), Map.of());
    SecuredOperationDescriptor onlyPerm = new SecuredOperationDescriptor(
        "c", "C", "", "rest", "/c", "do", Set.of(), Set.of(p), Map.of());
    SecuredOperationDescriptor both = new SecuredOperationDescriptor(
        "d", "D", "", "rest", "/d", "do", Set.of(r), Set.of(p), Map.of());

    assertTrue(noGates.isAuthenticatedOnly());
    assertFalse(onlyRole.isAuthenticatedOnly());
    assertFalse(onlyPerm.isAuthenticatedOnly());
    assertFalse(both.isAuthenticatedOnly());
  }

  @Test
  @DisplayName("descriptor constructor rejects blank id/label/resourceType/resourceName/operation")
  void descriptorRejectsBlanks() {
    assertThrows(IllegalArgumentException.class,
        () -> new SecuredOperationDescriptor(" ", "L", "", "rt", "rn", "op",
            Set.of(), Set.of(), Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> new SecuredOperationDescriptor("id", "", "", "rt", "rn", "op",
            Set.of(), Set.of(), Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> new SecuredOperationDescriptor("id", "L", "", " ", "rn", "op",
            Set.of(), Set.of(), Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> new SecuredOperationDescriptor("id", "L", "", "rt", "", "op",
            Set.of(), Set.of(), Map.of()));
    assertThrows(IllegalArgumentException.class,
        () -> new SecuredOperationDescriptor("id", "L", "", "rt", "rn", null,
            Set.of(), Set.of(), Map.of()));
  }
}
