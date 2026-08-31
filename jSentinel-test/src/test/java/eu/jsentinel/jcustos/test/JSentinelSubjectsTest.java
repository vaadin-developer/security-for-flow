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
package eu.jsentinel.jcustos.test;

import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JSentinelSubjectsTest {

  @Test
  @DisplayName("anonymousIdentity builds an empty-role/permission subject")
  void anonymousIdentity() {
    JSentinelSubject subject = JSentinelSubjects.anonymousIdentity("u-1");
    assertEquals("u-1", subject.subjectId());
    assertEquals("u-1", subject.displayName());
    assertTrue(subject.roles().isEmpty());
    assertTrue(subject.permissions().isEmpty());
  }

  @Test
  @DisplayName("withRoles builds a subject with the given role names")
  void withRoles() {
    JSentinelSubject subject = JSentinelSubjects.withRoles("u-1", "ROLE_ADMIN", "ROLE_EDITOR");
    assertEquals(Set.of(new RoleName("ROLE_ADMIN"), new RoleName("ROLE_EDITOR")),
        subject.roles());
    assertTrue(subject.permissions().isEmpty());
  }

  @Test
  @DisplayName("withPermissions builds a subject with the given permissions")
  void withPermissions() {
    JSentinelSubject subject = JSentinelSubjects.withPermissions("u-1", "doc:read", "doc:write");
    assertEquals(Set.of(new PermissionName("doc:read"), new PermissionName("doc:write")),
        subject.permissions());
    assertTrue(subject.roles().isEmpty());
  }

  @Test
  @DisplayName("of builds a subject with both roles and permissions")
  void ofBuildsBoth() {
    JSentinelSubject subject = JSentinelSubjects.of(
        "u-1", Set.of("ROLE_ADMIN"), Set.of("doc:read"));
    assertEquals(Set.of(new RoleName("ROLE_ADMIN")), subject.roles());
    assertEquals(Set.of(new PermissionName("doc:read")), subject.permissions());
  }
}
