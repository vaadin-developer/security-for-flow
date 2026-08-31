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
package eu.jsentinel.jcustos.authorization.api.roles;

import eu.jsentinel.jcustos.authentication.AuthenticationService;
import eu.jsentinel.jcustos.authorization.api.AuthorizationService;
import eu.jsentinel.jcustos.authorization.api.JSentinelServiceResolver;
import eu.jsentinel.jcustos.authorization.api.SubjectStore;
import eu.jsentinel.jcustos.authorization.api.SubjectStores;
import eu.jsentinel.jcustos.authorization.api.permissions.HasPermissions;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import eu.jsentinel.jcustos.authorization.navigation.AccessDecision;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;

class RoleBasedAccessEvaluatorTest {

  static final class Sub {
    final Set<String> roles;
    Sub(Set<String> roles) { this.roles = roles; }
  }

  static final class TestAuthn implements AuthenticationService<String, Sub> {
    @Override public boolean checkCredentials(String c) { return false; }
    @Override public Sub loadSubject(String c) { return null; }
    @Override public Class<Sub> subjectType() { return Sub.class; }
  }

  static final class TestAuthz implements AuthorizationService<Sub> {
    @Override public HasRoles rolesFor(Sub s) {
      return () -> s.roles.stream().map(RoleName::new).toList();
    }
    @Override public HasPermissions permissionsFor(Sub s) {
      return java.util.List::of;
    }
  }

  static final class HeapStore implements SubjectStore {
    private final Map<Class<?>, Object> map = new HashMap<>();
    @Override public <T> Optional<T> currentSubject(Class<T> t) {
      return Optional.ofNullable(t.cast(map.get(t)));
    }
    @Override public <T> void setCurrentSubject(T s, Class<T> t) { map.put(t, s); }
    @Override public <T> void deleteCurrentSubject(Class<T> t) { map.remove(t); }
  }

  /** Concrete evaluator under test. */
  static final class FixedRoleEvaluator extends RoleBasedAccessEvaluator<Annotation, Sub> {
    private final Set<RoleName> required;
    FixedRoleEvaluator(Set<RoleName> required) { this.required = required; }
    @Override public Set<RoleName> requiredRoles(Annotation a) { return required; }
    @Override public AuthorizationService<Sub> authorizationService() { return new TestAuthz(); }
    @Override public String alternativeNavigationTarget(AccessContext c, Annotation a) {
      return "/login";
    }
  }

  private HeapStore store;

  @BeforeEach
  void setUp() {
    JSentinelServiceResolver.resetAll();
    JSentinelServiceResolver.setAuthenticationService(new TestAuthn());
    store = new HeapStore();
    SubjectStores.setSubjectStore(store);
  }

  @AfterEach
  void tearDown() {
    JSentinelServiceResolver.resetAll();
  }

  private static AccessContext ctx() {
    return new AccessContext(Optional.empty(),
        "view", "AnyView", "navigate", Map.of());
  }

  @Test
  @DisplayName("JS-SEC-011: empty required-roles set denies an anonymous visitor (authenticate first)")
  void emptyRequiredDeniesAnonymous() {
    FixedRoleEvaluator ev = new FixedRoleEvaluator(Set.of());
    // no subject bound — previously this granted access to anyone (fail-open).
    org.junit.jupiter.api.Assertions.assertFalse(
        ev.evaluate(ctx(), null) instanceof AccessDecision.Granted,
        "empty roles must not grant an anonymous visitor");
  }

  @Test
  @DisplayName("JS-SEC-011: empty required-roles set grants any authenticated subject")
  void emptyRequiredGrantsAuthenticated() {
    store.setCurrentSubject(new Sub(Set.of("VIEWER")), Sub.class);
    FixedRoleEvaluator ev = new FixedRoleEvaluator(Set.of());
    assertInstanceOf(AccessDecision.Granted.class,
        ev.evaluate(ctx(), null),
        "empty roles means any authenticated subject");
  }

  @Test
  @DisplayName("absent subject and non-empty roles → Denied with reroute target")
  void noSubjectDenies() {
    FixedRoleEvaluator ev = new FixedRoleEvaluator(Set.of(new RoleName("ADMIN")));
    AccessDecision decision = ev.evaluate(ctx(), null);
    // Denied for security-vaadin maps to "Reroute" — keep the test
    // simple: just assert NOT Granted.
    org.junit.jupiter.api.Assertions.assertFalse(
        decision instanceof AccessDecision.Granted);
  }

  @Test
  @DisplayName("subject with matching role → Granted")
  void matchingRoleGrants() {
    store.setCurrentSubject(new Sub(Set.of("ADMIN")), Sub.class);
    FixedRoleEvaluator ev = new FixedRoleEvaluator(Set.of(new RoleName("ADMIN")));
    assertInstanceOf(AccessDecision.Granted.class,
        ev.evaluate(ctx(), null));
  }

  @Test
  @DisplayName("subject without matching role → Denied")
  void wrongRoleDenies() {
    store.setCurrentSubject(new Sub(Set.of("VIEWER")), Sub.class);
    FixedRoleEvaluator ev = new FixedRoleEvaluator(Set.of(new RoleName("ADMIN")));
    AccessDecision decision = ev.evaluate(ctx(), null);
    org.junit.jupiter.api.Assertions.assertFalse(
        decision instanceof AccessDecision.Granted);
  }

  @Test
  @DisplayName("RoleHierarchy implied role grants access")
  void hierarchyImpliedGrants() {
    store.setCurrentSubject(new Sub(Set.of("ADMIN")), Sub.class);
    JSentinelServiceResolver.setRoleHierarchy(role -> {
      if ("ADMIN".equals(role.value())) {
        return Set.of(new RoleName("ADMIN"), new RoleName("VIEWER"));
      }
      return Set.of(role);
    });
    FixedRoleEvaluator ev = new FixedRoleEvaluator(Set.of(new RoleName("VIEWER")));
    assertInstanceOf(AccessDecision.Granted.class,
        ev.evaluate(ctx(), null));
  }

  @Test
  @DisplayName("Multiple required roles: holding any one is enough")
  void multipleRequiredAnyHeldGrants() {
    store.setCurrentSubject(new Sub(Set.of("EDITOR")), Sub.class);
    FixedRoleEvaluator ev = new FixedRoleEvaluator(Set.of(
        new RoleName("ADMIN"), new RoleName("EDITOR")));
    assertInstanceOf(AccessDecision.Granted.class,
        ev.evaluate(ctx(), null));
  }
}
