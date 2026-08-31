/**
 * Copyright © 2018 Sven Ruppert (sven.ruppert@gmail.com)
 *
 * Licensed under the EUPL, Version 1.2 or - as soon they will be
 * approved by the European Commission - subsequent versions of the
 * EUPL (the "Licence"); You may not use this work except in
 * compliance with the Licence. You may obtain a copy of the Licence at:
 *
 * https://joinup.ec.europa.eu/software/page/eupl
 */
package eu.jsentinel.jcustos.starter.routes;

import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.api.permissions.PermissionName;
import eu.jsentinel.jcustos.authorization.api.roles.RoleName;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SecureRouteEvaluatorTest {

  private final SecureRouteEvaluator evaluator = new SecureRouteEvaluator();

  @Test
  void unauthenticated_whenSubjectMissingAndCheckSet() {
    AuthorizationDecision d = evaluator.evaluate(
        ctx(Optional.empty()),
        ann(new String[]{"ADMIN"}, new String[]{}, ""));
    assertInstanceOf(AuthorizationDecision.Unauthenticated.class, d);
  }

  @Test
  void granted_whenSubjectHasRole() {
    AuthorizationDecision d = evaluator.evaluate(
        ctx(Optional.of(subject(Set.of(new RoleName("ADMIN")), Set.of()))),
        ann(new String[]{"ADMIN"}, new String[]{}, ""));
    assertInstanceOf(AuthorizationDecision.Granted.class, d);
  }

  @Test
  void forbidden_whenSubjectLacksRoleAndPermission() {
    AuthorizationDecision d = evaluator.evaluate(
        ctx(Optional.of(subject(Set.of(new RoleName("USER")), Set.of()))),
        ann(new String[]{"ADMIN"}, new String[]{}, ""));
    assertInstanceOf(AuthorizationDecision.Forbidden.class, d);
  }

  @Test
  void permissionsAreAllOf() {
    JCustosSubject sub = subject(Set.of(),
        Set.of(new PermissionName("doc:read")));
    // Subject has only "doc:read"; annotation needs read+write.
    AuthorizationDecision d = evaluator.evaluate(ctx(Optional.of(sub)),
        ann(new String[]{}, new String[]{"doc:read", "doc:write"}, ""));
    assertInstanceOf(AuthorizationDecision.Forbidden.class, d);
  }

  @Test
  void combinedRolesAndPermissions_grantedOnlyWhenBoth() {
    // Subject has role ADMIN but not permission doc:write
    JCustosSubject sub = subject(Set.of(new RoleName("ADMIN")), Set.of());
    AuthorizationDecision d = evaluator.evaluate(ctx(Optional.of(sub)),
        ann(new String[]{"ADMIN"}, new String[]{"doc:write"}, ""));
    assertInstanceOf(AuthorizationDecision.Forbidden.class, d);
  }

  @Test
  void emptyAnnotation_deniesAnonymous() {
    // R035: a constraint-less @SecureRoute must NOT grant an anonymous visitor —
    // it means "any authenticated subject", so no subject => Unauthenticated.
    AuthorizationDecision d = evaluator.evaluate(
        ctx(Optional.empty()),
        ann(new String[]{}, new String[]{}, ""));
    assertInstanceOf(AuthorizationDecision.Unauthenticated.class, d);
  }

  @Test
  void emptyAnnotation_grantsAuthenticatedSubject() {
    // R035: with a subject bound, a constraint-less @SecureRoute means
    // "authenticated required" and admits any authenticated user.
    JCustosSubject sub = subject(Set.of(), Set.of());
    AuthorizationDecision d = evaluator.evaluate(
        ctx(Optional.of(sub)),
        ann(new String[]{}, new String[]{}, ""));
    assertInstanceOf(AuthorizationDecision.Granted.class, d);
  }

  @Test
  void policyAlone_isForbidden_v0072Limitation() {
    JCustosSubject sub = subject(Set.of(), Set.of());
    AuthorizationDecision d = evaluator.evaluate(ctx(Optional.of(sub)),
        ann(new String[]{}, new String[]{}, "doc.owner-or-admin"));
    assertInstanceOf(AuthorizationDecision.Forbidden.class, d);
    AuthorizationDecision.Forbidden f = (AuthorizationDecision.Forbidden) d;
    assertTrue(f.reason().contains("doc.owner-or-admin"));
  }

  // --- helpers -----------------------------------------------------------

  private static SecureRoute ann(String[] roles, String[] perms, String policy) {
    return new SecureRoute() {
      @Override public Class<? extends java.lang.annotation.Annotation> annotationType() {
        return SecureRoute.class;
      }
      @Override public String[] roles() { return roles; }
      @Override public String[] permissions() { return perms; }
      @Override public String policy() { return policy; }
    };
  }

  private static JCustosSubject subject(Set<RoleName> roles, Set<PermissionName> perms) {
    return new JCustosSubject("u1", "Test User", roles, perms);
  }

  private static AccessContext ctx(Optional<JCustosSubject> sub) {
    return new AccessContext(sub, "vaadin-route", "/test", "view", Map.of());
  }

  @Test
  void granted_whenSubjectHasAllPermissions() {
    JCustosSubject sub = subject(Set.of(),
        Set.of(new PermissionName("doc:read"), new PermissionName("doc:write")));
    AuthorizationDecision d = evaluator.evaluate(ctx(Optional.of(sub)),
        ann(new String[]{}, new String[]{"doc:read", "doc:write"}, ""));
    assertEquals(AuthorizationDecision.Granted.class, d.getClass());
  }
}
