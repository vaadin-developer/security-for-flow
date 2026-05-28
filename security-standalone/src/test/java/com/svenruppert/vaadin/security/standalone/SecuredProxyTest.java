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
package com.svenruppert.vaadin.security.standalone;

import com.svenruppert.vaadin.security.authentication.AuthenticationService;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.authorization.annotations.RequiresRole;
import com.svenruppert.vaadin.security.authorization.annotations.SecurityAnnotation;
import com.svenruppert.vaadin.security.authorization.api.AccessDeniedException;
import com.svenruppert.vaadin.security.authorization.api.AccessEvaluator;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationService;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.authorization.api.permissions.HasPermissions;
import com.svenruppert.vaadin.security.authorization.api.permissions.PermissionName;
import com.svenruppert.vaadin.security.authorization.api.roles.HasRoles;
import com.svenruppert.vaadin.security.authorization.api.roles.RoleName;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.authorization.navigation.AccessDecision;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

@DisplayName("SecuredProxy — dynamic-proxy enforcement")
class SecuredTest {

  @BeforeEach
  void setUp() throws Exception {
    SecurityServiceResolver.resetAll();
    installService("AUTHENTICATION_SERVICE_REF", new StubAuth());
    installService("AUTHORIZATION_SERVICE_REF", new StubAuthz());
    SubjectStores.reset();
    InMemoryStore.clear();
    SubjectStores.setSubjectStore(new InMemoryStore());
  }

  /**
   * SecurityServiceResolver has no public setter for the auth/authz
   * services — they are normally SPI-loaded. Reflectively install the
   * stubs into the resolver's AtomicReference fields.
   */
  private static void installService(String fieldName, Object service) throws Exception {
    java.lang.reflect.Field f = SecurityServiceResolver.class.getDeclaredField(fieldName);
    f.setAccessible(true);
    @SuppressWarnings("unchecked")
    java.util.concurrent.atomic.AtomicReference<Object> ref =
        (java.util.concurrent.atomic.AtomicReference<Object>) f.get(null);
    ref.set(service);
  }

  @AfterEach
  void tearDown() {
    SecurityServiceResolver.resetAll();
    SubjectStores.reset();
    InMemoryStore.clear();
  }

  // ── wrap requires interface ────────────────────────────────────

  @Test
  @DisplayName("wrap() rejects a non-interface class")
  void wrapRejectsClass() {
    assertThrows(IllegalArgumentException.class,
        () -> SecuredProxy.wrap(String.class, "x"));
  }

  // ── Object methods bypass enforcement ─────────────────────────

  @Test
  @DisplayName("Object methods (equals/hashCode/toString) bypass enforcement entirely")
  void objectMethodsBypass() {
    Service delegate = new ServiceImpl();
    Service secured = SecuredProxy.wrap(Service.class, delegate);

    assertNotNull(secured.toString());
    assertEquals(secured.hashCode(), secured.hashCode());
    // No exception thrown — no subject bound, so if Object methods went
    // through enforcement they would throw AccessDeniedException.
  }

  // ── Unannotated method passes through ─────────────────────────

  @Test
  @DisplayName("Unannotated method calls bypass enforcement and reach the delegate")
  void unannotatedPassesThrough() {
    Service secured = SecuredProxy.wrap(Service.class, new ServiceImpl());
    assertEquals("open", secured.openOperation(),
        "an unannotated method must run on the delegate without enforcement");
  }

  // ── Annotated method, no subject → Reroute / Unauthenticated ──

  @Test
  @DisplayName("Annotated method without a bound subject throws AccessDeniedException")
  void annotatedWithoutSubjectIsDenied() {
    Service secured = SecuredProxy.wrap(Service.class, new ServiceImpl());
    assertThrows(AccessDeniedException.class, secured::listItems,
        "@RequiresPermission must be enforced — anonymous call must throw");
  }

  // ── Annotated method, subject has permission → delegate runs ──

  @Test
  @DisplayName("@RequiresPermission allows a subject that holds the permission")
  void permissionGrantedReachesDelegate() {
    bindSubject("alice", Set.of(), Set.of(new PermissionName("test:list")));
    ServiceImpl impl = new ServiceImpl();
    Service secured = SecuredProxy.wrap(Service.class, impl);

    List<String> items = secured.listItems();

    assertEquals(List.of("a", "b"), items);
    assertEquals(1, impl.listCalls.get(),
        "the delegate must be called exactly once for a granted permission check");
  }

  // ── Annotated method, subject without permission → Forbidden → AccessDeniedException ──

  @Test
  @DisplayName("@RequiresPermission denies a subject without the permission (Forbidden branch)")
  void permissionForbidden() {
    bindSubject("alice", Set.of(), Set.of());
    Service secured = SecuredProxy.wrap(Service.class, new ServiceImpl());

    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        secured::listItems);
    assertTrue(ex.getMessage().contains("Missing required permission")
            || ex.getMessage().contains("Access denied"),
        "Forbidden branch must surface a meaningful message; got: " + ex.getMessage());
  }

  // ── @RequiresRole branch ──────────────────────────────────────

  @Test
  @DisplayName("@RequiresRole allows a subject that holds the role")
  void roleGranted() {
    bindSubject("admin", Set.of(new RoleName("ADMIN")), Set.of());
    Service secured = SecuredProxy.wrap(Service.class, new ServiceImpl());

    secured.adminAction();
  }

  @Test
  @DisplayName("@RequiresRole denies a subject without the role")
  void roleForbidden() {
    bindSubject("alice", Set.of(new RoleName("USER")), Set.of());
    Service secured = SecuredProxy.wrap(Service.class, new ServiceImpl());

    assertThrows(AccessDeniedException.class, secured::adminAction);
  }

  // ── Class-level annotation falls through to method-level scan ─

  @Test
  @DisplayName("Class-level annotation guards every method (even unannotated ones)")
  void classLevelAnnotation() {
    GuardedService secured = SecuredProxy.wrap(GuardedService.class, new GuardedServiceImpl());

    // Without a subject → denied
    assertThrows(AccessDeniedException.class, secured::ping);

    // With the right role → granted
    bindSubject("admin", Set.of(new RoleName("ADMIN")), Set.of());
    assertEquals("pong", secured.ping(),
        "class-level @RequiresRole must allow calls when the subject holds the role");
  }

  // ── Custom AccessEvaluator branch ─────────────────────────────

  @Test
  @DisplayName("Custom AccessEvaluator path returns Granted → delegate runs")
  void customAccessEvaluatorGrants() {
    SettableEvaluator.next = AccessDecision.granted();
    bindSubject("alice", Set.of(), Set.of());
    Service secured = SecuredProxy.wrap(Service.class, new ServiceImpl());

    secured.customCheck();
    assertEquals(1, SettableEvaluator.invocations,
        "the AccessEvaluator branch must run exactly once");
  }

  @Test
  @DisplayName("Custom AccessEvaluator path returns RerouteToError → AccessDeniedException")
  void customAccessEvaluatorRerouteToError() {
    SettableEvaluator.next = AccessDecision.rerouteToError(
        SecurityException.class, "nope");
    bindSubject("alice", Set.of(), Set.of());
    Service secured = SecuredProxy.wrap(Service.class, new ServiceImpl());

    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        secured::customCheck);
    assertEquals("nope", ex.getMessage());
  }

  @Test
  @DisplayName("Custom AccessEvaluator path returns Reroute → AccessDeniedException with target")
  void customAccessEvaluatorReroute() {
    SettableEvaluator.next = AccessDecision.reroute("home", false);
    bindSubject("alice", Set.of(), Set.of());
    Service secured = SecuredProxy.wrap(Service.class, new ServiceImpl());

    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        secured::customCheck);
    assertTrue(ex.getMessage().contains("home"),
        "Reroute decision must mention the target route in the exception message");
  }

  // ── AuthorizationEvaluator StepUp branch ──────────────────────

  @Test
  @DisplayName("AuthorizationEvaluator returns StepUpRequired → AccessDeniedException naming method + reason")
  void authorizationEvaluatorStepUpThrows() {
    bindSubject("alice", Set.of(), Set.of());
    Service secured = SecuredProxy.wrap(Service.class, new ServiceImpl());

    AccessDeniedException ex = assertThrows(AccessDeniedException.class,
        secured::sensitiveAction);
    assertEquals("Step-up required: method=MFA, reason=needs mfa", ex.getMessage(),
        "StepUpRequired must surface as AccessDeniedException whose message "
            + "names both the requested step-up method and the reason from the decision");
  }

  // ── Checked-exception propagation ─────────────────────────────

  @Test
  @DisplayName("Delegate exceptions propagate verbatim (no InvocationTargetException)")
  void delegateExceptionsPropagate() {
    bindSubject("alice", Set.of(), Set.of(new PermissionName("test:list")));
    Service secured = SecuredProxy.wrap(Service.class, new ThrowingService());

    IllegalStateException ex = assertThrows(IllegalStateException.class,
        secured::listItems);
    assertEquals("delegate-boom", ex.getMessage(),
        "the proxy must unwrap InvocationTargetException so callers see the original cause");
  }

  // ── requireAllowed(Class, methodName) ─────────────────────────

  @Test
  @DisplayName("requireAllowed throws for an unknown method name")
  void requireAllowedUnknownMethod() {
    assertThrows(IllegalArgumentException.class,
        () -> SecuredProxy.requireAllowed(Service.class, "doesNotExist"));
  }

  @Test
  @DisplayName("requireAllowed runs the matching evaluator and throws on deny")
  void requireAllowedDeny() {
    // No subject bound → @RequiresPermission on the interface method
    // → Unauthenticated → AccessDeniedException
    assertThrows(AccessDeniedException.class,
        () -> SecuredProxy.requireAllowed(Service.class, "listItems"));
  }

  @Test
  @DisplayName("requireAllowed is a no-op when neither method nor declaring class is annotated")
  void requireAllowedNoAnnotation() {
    // openOperation is unannotated — no enforcement, no exception
    SecuredProxy.requireAllowed(Service.class, "openOperation");
  }

  // ── Helpers ────────────────────────────────────────────────────

  private static void bindSubject(String id, Set<RoleName> roles, Set<PermissionName> perms) {
    InMemoryStore.STORE.put(String.class, id);
    StubAuthz.ROLES.put(id, roles);
    StubAuthz.PERMS.put(id, perms);
  }

  // ── Fixtures ──────────────────────────────────────────────────

  public interface Service {
    @RequiresPermission("test:list")
    List<String> listItems();

    @RequiresRole("ADMIN")
    void adminAction();

    @CustomCheck
    void customCheck();

    @DemandsStepUp
    void sensitiveAction();

    String openOperation();
  }

  public static class ServiceImpl implements Service {
    final AtomicInteger listCalls = new AtomicInteger();

    @Override public List<String> listItems() {
      listCalls.incrementAndGet();
      return List.of("a", "b");
    }

    @Override public void adminAction() { /* noop */ }

    @Override public void customCheck() { /* noop */ }

    @Override public void sensitiveAction() { /* noop */ }

    @Override public String openOperation() { return "open"; }
  }

  public static class ThrowingService implements Service {
    @Override public List<String> listItems() {
      throw new IllegalStateException("delegate-boom");
    }
    @Override public void adminAction() { }
    @Override public void customCheck() { }
    @Override public void sensitiveAction() { }
    @Override public String openOperation() { return ""; }
  }

  // Custom annotation + AuthorizationEvaluator that always returns
  // StepUpRequired — exercises the AuthorizationDecision branch of
  // SecuredProxy.run().
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.METHOD, ElementType.TYPE})
  @SecurityAnnotation(StepUpDemandingEvaluator.class)
  public @interface DemandsStepUp { }

  public static class StepUpDemandingEvaluator
      implements com.svenruppert.vaadin.security.authorization.api.AuthorizationEvaluator<DemandsStepUp> {
    @Override
    public com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision evaluate(
        AccessContext context, DemandsStepUp annotation) {
      return com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision
          .stepUpRequired("needs mfa", "MFA");
    }
  }

  @RequiresRole("ADMIN")
  public interface GuardedService {
    String ping();
  }

  public static class GuardedServiceImpl implements GuardedService {
    @Override public String ping() { return "pong"; }
  }

  // Custom annotation + AccessEvaluator to exercise the AccessEvaluator branch
  // (the SettableEvaluator returns whatever the test stages in `next`).
  @Retention(RetentionPolicy.RUNTIME)
  @Target({ElementType.METHOD, ElementType.TYPE})
  @SecurityAnnotation(SettableEvaluator.class)
  public @interface CustomCheck { }

  public static class SettableEvaluator implements AccessEvaluator<CustomCheck> {
    static AccessDecision next = AccessDecision.granted();
    static int invocations = 0;

    @Override public AccessDecision evaluate(AccessContext context, CustomCheck annotation) {
      invocations++;
      return next;
    }
  }

  // ── Stub services ─────────────────────────────────────────────

  public static class StubAuth implements AuthenticationService<String, String> {
    @Override public boolean checkCredentials(String credentials) { return true; }
    @Override public String loadSubject(String credentials) { return credentials; }
    @Override public Class<String> subjectType() { return String.class; }
  }

  public static class StubAuthz implements AuthorizationService<String> {
    static final Map<String, Set<RoleName>> ROLES = new HashMap<>();
    static final Map<String, Set<PermissionName>> PERMS = new HashMap<>();

    @Override public HasRoles rolesFor(String subject) {
      return () -> List.copyOf(ROLES.getOrDefault(subject, Set.of()));
    }
    @Override public HasPermissions permissionsFor(String subject) {
      return () -> List.copyOf(PERMS.getOrDefault(subject, Set.of()));
    }
  }

  static final class InMemoryStore implements com.svenruppert.vaadin.security.authorization.api.SubjectStore {
    static final Map<Class<?>, Object> STORE = new HashMap<>();

    static void clear() { STORE.clear(); StubAuthz.ROLES.clear(); StubAuthz.PERMS.clear(); SettableEvaluator.invocations = 0; SettableEvaluator.next = AccessDecision.granted(); }

    @Override public <T> Optional<T> currentSubject(Class<T> subjectType) {
      return Optional.ofNullable(subjectType.cast(STORE.get(subjectType)));
    }
    @Override public <T> void setCurrentSubject(T subject, Class<T> subjectType) {
      STORE.put(subjectType, subject);
    }
    @Override public <T> void deleteCurrentSubject(Class<T> subjectType) {
      STORE.remove(subjectType);
    }
  }
}
