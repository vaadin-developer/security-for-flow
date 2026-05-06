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
package com.svenruppert.vaadin.security.authorization.api.operations;

import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
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

    SecuritySubject viewer = new SecuritySubject("u", "Viewer",
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

    SecuritySubject anon = new SecuritySubject("u", "Any", Set.of(), Set.of());
    assertEquals(1, service.visibleFor(anon).size());
  }
}
