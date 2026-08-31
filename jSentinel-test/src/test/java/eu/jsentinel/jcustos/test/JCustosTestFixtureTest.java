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

import eu.jsentinel.jcustos.authorization.api.JCustosServiceResolver;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class JCustosTestFixtureTest {

  @AfterEach
  void tearDown() {
    SubjectStores.findSubjectStore()
        .ifPresent(store -> store.deleteCurrentSubject(JCustosSubject.class));
    JCustosServiceResolver.resetAll();
  }

  @Test
  @DisplayName("build() binds subject with the declared roles and permissions")
  void buildBindsSubject() {
    try (JCustosTestFixture fixture = JCustosTestFixture.builder()
        .subject("alice")
        .role("ROLE_ADMIN")
        .permission("doc:read")
        .permission("doc:write")
        .build()) {

      JCustosSubject subject = fixture.subject();
      assertEquals("alice", subject.subjectId());
      assertEquals("alice", subject.displayName());
      assertTrue(subject.roles().contains(new RoleName("ROLE_ADMIN")));
      assertTrue(subject.permissions().contains(new PermissionName("doc:read")));
      assertTrue(subject.permissions().contains(new PermissionName("doc:write")));

      JCustosSubject bound = SubjectStores.subjectStore()
          .currentSubject(JCustosSubject.class)
          .orElseThrow();
      assertSame(subject, bound);
    }
  }

  @Test
  @DisplayName("displayName overrides subject id")
  void displayNameOverride() {
    try (JCustosTestFixture fixture = JCustosTestFixture.builder()
        .subject("alice")
        .displayName("Alice Admin")
        .role("ROLE_ADMIN")
        .build()) {

      assertEquals("Alice Admin", fixture.subject().displayName());
    }
  }

  @Test
  @DisplayName("roles(varargs) and permissions(varargs) accept multiple at once")
  void varargsHelpers() {
    try (JCustosTestFixture fixture = JCustosTestFixture.builder()
        .subject("bob")
        .roles("R1", "R2")
        .permissions("p:a", "p:b")
        .build()) {

      Set<RoleName> roles = fixture.subject().roles();
      assertTrue(roles.contains(new RoleName("R1")));
      assertTrue(roles.contains(new RoleName("R2")));
      Set<PermissionName> perms = fixture.subject().permissions();
      assertTrue(perms.contains(new PermissionName("p:a")));
      assertTrue(perms.contains(new PermissionName("p:b")));
    }
  }

  @Test
  @DisplayName("close() clears the current-subject binding")
  void closeClearsBinding() {
    JCustosTestFixture fixture = JCustosTestFixture.builder()
        .subject("temp")
        .role("ROLE_X")
        .build();

    assertTrue(SubjectStores.subjectStore()
        .currentSubject(JCustosSubject.class).isPresent());

    fixture.close();

    assertFalse(SubjectStores.subjectStore()
        .currentSubject(JCustosSubject.class).isPresent());
  }

  @Test
  @DisplayName("build() rejects missing subject id")
  void buildRequiresSubject() {
    assertThrows(IllegalStateException.class,
        () -> JCustosTestFixture.builder().build());
  }

  @Test
  @DisplayName("runAs(...) binds for the block and clears afterwards")
  void runAsBindsAndClears() {
    JCustosSubject admin = new JCustosSubject(
        "admin", "Admin",
        Set.of(new RoleName("ROLE_ADMIN")),
        Set.of(new PermissionName("doc:delete"))
    );
    SubjectStores.setSubjectStore(new InMemorySubjectStore());

    AtomicBoolean entered = new AtomicBoolean(false);
    JCustosTestFixture.runAs(admin, () -> {
      entered.set(true);
      assertSame(admin, SubjectStores.subjectStore()
          .currentSubject(JCustosSubject.class).orElseThrow());
    });

    assertTrue(entered.get());
    assertFalse(SubjectStores.subjectStore()
        .currentSubject(JCustosSubject.class).isPresent());
  }
}
