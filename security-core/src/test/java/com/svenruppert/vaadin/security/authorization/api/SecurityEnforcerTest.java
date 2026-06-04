/*-
 * #%L
 * Security Core
 * %%
 * Copyright (C) 2018 - 2026 Sven Ruppert
 * %%
 * Licensed under the EUPL, Version 1.1 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence");
 *
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 *
 * http://ec.europa.eu/idabc/eupl5
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * #L%
 */
package com.svenruppert.vaadin.security.authorization.api;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresAllPermissions;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresAnyPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPolicy;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresRole;
import com.svenruppert.vaadin.security.authorization.api.permissions.HasPermissions;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.HasRoles;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleHierarchy;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.policy.api.Policy;
import com.svenruppert.vaadin.security.policy.api.PolicyContext;
import com.svenruppert.vaadin.security.policy.api.PolicyDecision;
import com.svenruppert.vaadin.security.policy.spi.PolicyRegistry;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecurityEnforcerTest {

  static final class TestUser {
    final String name;
    final Set<String> roles;
    final Set<String> perms;

    TestUser(String name, Set<String> roles, Set<String> perms) {
      this.name = name;
      this.roles = roles;
      this.perms = perms;
    }

    @Override public String toString() { return name; }
  }

  static final class TestAuthn implements AuthenticationService<String, TestUser> {
    @Override public boolean checkCredentials(String creds) { return false; }
    @Override public TestUser loadSubject(String creds) { return null; }
    @Override public Class<TestUser> subjectType() { return TestUser.class; }
  }

  static final class TestAuthz implements AuthorizationService<TestUser> {
    @Override public HasRoles rolesFor(TestUser u) {
      return () -> u.roles.stream().map(RoleName::new).toList();
    }
    @Override public HasPermissions permissionsFor(TestUser u) {
      return () -> u.perms.stream().map(PermissionName::new).toList();
    }
  }

  /** In-memory SubjectStore that ignores hard ThreadLocal vs Vaadin choice. */
  static final class HeapSubjectStore implements SubjectStore {
    private final Map<Class<?>, Object> store = new HashMap<>();
    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      Object v = store.get(subjectType);
      return Optional.ofNullable(subjectType.cast(v));
    }
    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      store.put(subjectType, subject);
    }
    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
      store.remove(subjectType);
    }
  }

  /** Registry that maps a fixed name to a fixed decision. */
  static final class FixedRegistry implements PolicyRegistry {
    private final Map<String, PolicyDecision> map = new HashMap<>();
    void bind(String name, PolicyDecision decision) { map.put(name, decision); }
    @Override public Optional<Policy> find(String name) { return Optional.empty(); }
    @Override public void register(Policy policy) { /* unused in this test */ }
    @Override public PolicyDecision evaluate(String name, PolicyContext ctx) {
      PolicyDecision d = map.get(name);
      if (d == null) {
        throw new IllegalStateException("unknown policy: " + name);
      }
      return d;
    }
  }

  private HeapSubjectStore store;
  private FixedRegistry policies;

  @BeforeEach
  void setUp() {
    SecurityServiceResolver.resetAll();
    SecurityServiceResolver.setAuthenticationService(new TestAuthn());
    SecurityServiceResolver.setAuthorizationService(new TestAuthz());
    store = new HeapSubjectStore();
    SubjectStores.setSubjectStore(store);
    policies = new FixedRegistry();
    SecurityServiceResolver.setPolicyRegistry(policies);
  }

  @AfterEach
  void tearDown() {
    SecurityServiceResolver.resetAll();
  }

  private void bind(TestUser user) {
    store.setCurrentSubject(user, TestUser.class);
  }

  // ── requirePermission / requireAllPermissions ─────────────────────

  @Test
  @DisplayName("requirePermission passes when subject holds it")
  void requirePermissionHeld() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    assertDoesNotThrow(() -> SecurityEnforcer.requirePermission("doc:read"));
  }

  @Test
  @DisplayName("requirePermission throws when subject misses it")
  void requirePermissionMissing() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> SecurityEnforcer.requirePermission("doc:delete"));
    assertTrue(ex.getMessage().contains("doc:delete"));
  }

  @Test
  @DisplayName("requirePermission throws when no subject is bound")
  void requirePermissionNoSubject() {
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> SecurityEnforcer.requirePermission("doc:read"));
    assertTrue(ex.getMessage().contains("No authenticated subject"));
  }

  @Test
  @DisplayName("requireAllPermissions passes when subject holds every one")
  void requireAllPermissionsHeld() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read", "doc:write")));
    assertDoesNotThrow(() -> SecurityEnforcer.requireAllPermissions("doc:read", "doc:write"));
  }

  @Test
  @DisplayName("requireAllPermissions throws when one is missing")
  void requireAllPermissionsOneMissing() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> SecurityEnforcer.requireAllPermissions("doc:read", "doc:write"));
    assertTrue(ex.getMessage().contains("doc:read"));
    assertTrue(ex.getMessage().contains("doc:write"));
  }

  @Test
  @DisplayName("requireAllPermissions rejects empty/null input with IAE")
  void requireAllPermissionsEmpty() {
    bind(new TestUser("alice", Set.of(), Set.of()));
    assertThrows(IllegalArgumentException.class,
        () -> SecurityEnforcer.requireAllPermissions());
    assertThrows(IllegalArgumentException.class,
        () -> SecurityEnforcer.requireAllPermissions((String[]) null));
  }

  // ── requireAnyPermission ──────────────────────────────────────────

  @Test
  @DisplayName("requireAnyPermission passes when any candidate held")
  void requireAnyPermissionOneHeld() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    assertDoesNotThrow(() -> SecurityEnforcer.requireAnyPermission("doc:write", "doc:read"));
  }

  @Test
  @DisplayName("requireAnyPermission throws when none held")
  void requireAnyPermissionNoneHeld() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> SecurityEnforcer.requireAnyPermission("doc:delete", "doc:purge"));
    assertTrue(ex.getMessage().contains("doc:delete"));
    assertTrue(ex.getMessage().contains("doc:purge"));
  }

  @Test
  @DisplayName("requireAnyPermission rejects empty input")
  void requireAnyPermissionEmpty() {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    assertThrows(IllegalArgumentException.class,
        () -> SecurityEnforcer.requireAnyPermission());
    assertThrows(IllegalArgumentException.class,
        () -> SecurityEnforcer.requireAnyPermission((String[]) null));
  }

  // ── requireRole / requireAnyRole ──────────────────────────────────

  @Test
  @DisplayName("requireRole passes when subject holds it")
  void requireRoleHeld() {
    bind(new TestUser("alice", Set.of("ADMIN"), Set.of()));
    assertDoesNotThrow(() -> SecurityEnforcer.requireRole("ADMIN"));
  }

  @Test
  @DisplayName("requireRole throws when subject misses it")
  void requireRoleMissing() {
    bind(new TestUser("alice", Set.of("VIEWER"), Set.of()));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> SecurityEnforcer.requireRole("ADMIN"));
    assertTrue(ex.getMessage().contains("ADMIN"));
  }

  @Test
  @DisplayName("requireAnyRole honours role hierarchy")
  void requireAnyRoleHonoursHierarchy() {
    bind(new TestUser("alice", Set.of("ADMIN"), Set.of()));
    SecurityServiceResolver.setRoleHierarchy(new RoleHierarchy() {
      @Override public Set<RoleName> impliedRoles(RoleName role) {
        if ("ADMIN".equals(role.value())) {
          return Set.of(new RoleName("ADMIN"), new RoleName("VIEWER"));
        }
        return Set.of(role);
      }
    });
    // VIEWER is implied by ADMIN — must pass
    assertDoesNotThrow(() -> SecurityEnforcer.requireRole("VIEWER"));
  }

  @Test
  @DisplayName("requireAnyRole rejects empty input")
  void requireAnyRoleEmpty() {
    bind(new TestUser("alice", Set.of("ADMIN"), Set.of()));
    assertThrows(IllegalArgumentException.class,
        () -> SecurityEnforcer.requireAnyRole());
    assertThrows(IllegalArgumentException.class,
        () -> SecurityEnforcer.requireAnyRole((String[]) null));
  }

  // ── requirePolicy ─────────────────────────────────────────────────

  @Test
  @DisplayName("requirePolicy with Allowed decision falls through")
  void requirePolicyAllowed() {
    bind(new TestUser("alice", Set.of(), Set.of()));
    policies.bind("any-policy", PolicyDecision.allowed("ok"));
    assertDoesNotThrow(() -> SecurityEnforcer.requirePolicy("any-policy"));
  }

  @Test
  @DisplayName("requirePolicy with Denied throws with the policy reason")
  void requirePolicyDenied() {
    bind(new TestUser("alice", Set.of(), Set.of()));
    policies.bind("doc-owner", PolicyDecision.denied("not the owner"));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> SecurityEnforcer.requirePolicy("doc-owner"));
    assertTrue(ex.getMessage().contains("doc-owner"));
    assertTrue(ex.getMessage().contains("not the owner"));
  }

  @Test
  @DisplayName("requirePolicy with StepUpRequired throws with method + reason")
  void requirePolicyStepUp() {
    bind(new TestUser("alice", Set.of(), Set.of()));
    policies.bind("doc-sensitive",
        PolicyDecision.stepUpRequired("high-value operation",
            PolicyDecision.StepUpMethod.MFA));
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> SecurityEnforcer.requirePolicy("doc-sensitive"));
    assertTrue(ex.getMessage().contains("step-up"));
    assertTrue(ex.getMessage().contains("MFA"));
    assertTrue(ex.getMessage().contains("high-value operation"));
  }

  @Test
  @DisplayName("requirePolicy 4-arg overload propagates resource/operation into the context")
  void requirePolicyWithContext() {
    bind(new TestUser("alice", Set.of(), Set.of()));
    final AccessContext[] captured = new AccessContext[1];
    PolicyRegistry capturing = new PolicyRegistry() {
      @Override public Optional<Policy> find(String name) { return Optional.empty(); }
      @Override public void register(Policy policy) { /* unused */ }
      @Override public PolicyDecision evaluate(String n, PolicyContext c) {
        captured[0] = c.accessContext();
        return PolicyDecision.allowed("ok");
      }
    };
    SecurityServiceResolver.setPolicyRegistry(capturing);
    SecurityEnforcer.requirePolicy("doc.read", "document", "doc-42", "read");
    assertEquals("document", captured[0].resourceType());
    assertEquals("doc-42", captured[0].resourceName());
    assertEquals("read", captured[0].operation());
  }

  // ── enforce(...) generic path ─────────────────────────────────────

  @RequiresPermission("doc:read")
  static class AnnotatedClass {
    public void readDoc() {}
    public void unrelated() {}
  }

  @RequiresRole("ADMIN")
  static class AdminClass {
    public void adminOnly() {}
  }

  @Test
  @DisplayName("enforce reads class-level @RequiresPermission and passes when held")
  void enforceClassLevelPermissionHeld() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    Method m = AnnotatedClass.class.getMethod("readDoc");
    assertDoesNotThrow(() -> SecurityEnforcer.enforce(m, AnnotatedClass.class));
  }

  @Test
  @DisplayName("enforce throws when subject lacks the class-level permission")
  void enforceClassLevelPermissionMissing() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of()));
    Method m = AnnotatedClass.class.getMethod("readDoc");
    assertThrows(AccessDeniedException.class,
        () -> SecurityEnforcer.enforce(m, AnnotatedClass.class));
  }

  @Test
  @DisplayName("enforce reads class-level @RequiresRole")
  void enforceClassLevelRole() throws Exception {
    bind(new TestUser("alice", Set.of("ADMIN"), Set.of()));
    Method m = AdminClass.class.getMethod("adminOnly");
    assertDoesNotThrow(() -> SecurityEnforcer.enforce(m, AdminClass.class));
  }

  @Test
  @DisplayName("enforce on an unannotated element is a no-op")
  void enforceUnannotated() throws Exception {
    // No annotation on this class — no subject required
    Method m = NoAnnotationClass.class.getMethod("doStuff");
    assertDoesNotThrow(
        () -> SecurityEnforcer.enforce(m, NoAnnotationClass.class));
  }

  static class NoAnnotationClass {
    public void doStuff() {}
  }

  @Test
  @DisplayName("enforce(Method, Class) overload delegates with method name")
  void enforceMethodClassOverload() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of("doc:read")));
    Method m = AnnotatedClass.class.getMethod("readDoc");
    assertDoesNotThrow(() -> SecurityEnforcer.enforce(m, AnnotatedClass.class));
  }

  // ── method-level annotations ──────────────────────────────────────

  static class MixedClass {
    @RequiresAnyPermission({"a", "b"})
    public void either() {}

    @RequiresAllPermissions({"a", "b"})
    public void both() {}

    @RequiresPolicy("doc.policy")
    public void policy() {}
  }

  @Test
  @DisplayName("enforce respects @RequiresAnyPermission at method level")
  void enforceAnyPermission() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of("b")));
    Method m = MixedClass.class.getMethod("either");
    assertDoesNotThrow(() -> SecurityEnforcer.enforce(m, MixedClass.class));
  }

  @Test
  @DisplayName("enforce respects @RequiresAllPermissions at method level")
  void enforceAllPermissions() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of("a")));
    Method m = MixedClass.class.getMethod("both");
    assertThrows(AccessDeniedException.class,
        () -> SecurityEnforcer.enforce(m, MixedClass.class));
  }

  @Test
  @DisplayName("enforce respects @RequiresPolicy at method level")
  void enforceRequiresPolicy() throws Exception {
    bind(new TestUser("alice", Set.of(), Set.of()));
    policies.bind("doc.policy", PolicyDecision.denied("nope"));
    Method m = MixedClass.class.getMethod("policy");
    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        () -> SecurityEnforcer.enforce(m, MixedClass.class));
    assertTrue(ex.getMessage().contains("nope"));
  }
}
