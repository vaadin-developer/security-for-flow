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
package com.svenruppert.jsentinel.authorization.impl;

import com.svenruppert.jsentinel.authorization.api.AccessEvaluator;
import com.svenruppert.jsentinel.authorization.api.AuthorizationDecision;
import com.svenruppert.jsentinel.authorization.api.AuthorizationEvaluator;
import com.svenruppert.jsentinel.authorization.navigation.AccessContext;
import com.svenruppert.jsentinel.authorization.navigation.AccessDecision;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Exercises the private {@code evaluate(Object, AccessContext, Annotation)}
 * and {@code map(AuthorizationDecision)} helpers directly via reflection.
 * These are the decision-mapping core of {@link AuthorizationListener} and
 * are otherwise only reachable via a full Vaadin navigation lifecycle.
 */
@DisplayName("AuthorizationListener — evaluate + map")
class AuthorizationListenerEvaluateAndMapTest {

  private final AuthorizationListener listener = new AuthorizationListener();

  // ── evaluate(Object, AccessContext, Annotation) ───────────────

  @Test
  @DisplayName("evaluate delegates to AccessEvaluator and returns its AccessDecision verbatim")
  void evaluate_accessEvaluatorBranch() throws Exception {
    AccessDecision sentinel = AccessDecision.granted();
    AccessEvaluator<Annotation> evaluator = (ctx, ann) -> sentinel;

    Object result = invokeEvaluate(evaluator, ctx(), markerAnnotation());

    assertSame(sentinel, result,
        "AccessEvaluator branch must forward the evaluator's decision unchanged");
  }

  @Test
  @DisplayName("evaluate maps AuthorizationEvaluator(Granted) to AccessDecision.granted")
  void evaluate_authorizationGranted() throws Exception {
    AuthorizationEvaluator<Annotation> evaluator =
        (ctx, ann) -> new AuthorizationDecision.Granted();

    Object result = invokeEvaluate(evaluator, ctx(), markerAnnotation());

    assertInstanceOf(AccessDecision.Granted.class, result);
  }

  @Test
  @DisplayName("evaluate maps AuthorizationEvaluator(Unauthenticated) to forwarded reroute(login,false)")
  void evaluate_authorizationUnauthenticated() throws Exception {
    AuthorizationEvaluator<Annotation> evaluator =
        (ctx, ann) -> new AuthorizationDecision.Unauthenticated("not signed in");

    Object result = invokeEvaluate(evaluator, ctx(), markerAnnotation());

    assertInstanceOf(AccessDecision.Reroute.class, result);
    AccessDecision.Reroute reroute = (AccessDecision.Reroute) result;
    assertEquals("login", reroute.target());
    assertEquals(false, reroute.asForward());
  }

  @Test
  @DisplayName("evaluate maps Forbidden to deniedWithError with a GENERIC message — the reason is not leaked (R018)")
  void evaluate_authorizationForbidden() throws Exception {
    AuthorizationEvaluator<Annotation> evaluator =
        (ctx, ann) -> new AuthorizationDecision.Forbidden("missing permission document:42");

    Object result = invokeEvaluate(evaluator, ctx(), markerAnnotation());

    assertInstanceOf(AccessDecision.RerouteToError.class, result);
    AccessDecision.RerouteToError err = (AccessDecision.RerouteToError) result;
    assertEquals(SecurityException.class, err.type());
    // R018: the user-facing message must be generic and must NOT echo the
    // evaluator's internal reason (which could carry ids / policy names / SQL).
    assertEquals("Access denied", err.message());
    assertFalse(err.message().contains("document:42"),
        "the internal reason must never reach the user-facing error view");
  }

  @Test
  @DisplayName("evaluate throws IllegalStateException for unsupported evaluator types")
  void evaluate_unsupportedType_throws() {
    Object notAnEvaluator = new Object();

    InvocationTargetException ite = org.junit.jupiter.api.Assertions.assertThrows(
        InvocationTargetException.class,
        () -> invokeEvaluate(notAnEvaluator, ctx(), markerAnnotation()));
    assertInstanceOf(IllegalStateException.class, ite.getCause());
    assertTrue(ite.getCause().getMessage().contains("Unsupported evaluator type"));
    assertTrue(ite.getCause().getMessage().contains(Object.class.getName()));
  }

  // ── map(AuthorizationDecision) ────────────────────────────────

  @Test
  @DisplayName("map(Granted) → AccessDecision.Granted")
  void map_granted() throws Exception {
    Object result = invokeMap(new AuthorizationDecision.Granted());
    assertInstanceOf(AccessDecision.Granted.class, result);
  }

  @Test
  @DisplayName("map(Unauthenticated) → AccessDecision.Reroute(\"login\", false), regardless of reason")
  void map_unauthenticated() throws Exception {
    Object result = invokeMap(new AuthorizationDecision.Unauthenticated("any reason"));
    assertInstanceOf(AccessDecision.Reroute.class, result);
    AccessDecision.Reroute reroute = (AccessDecision.Reroute) result;
    assertEquals("login", reroute.target());
    assertEquals(false, reroute.asForward());
  }

  @Test
  @DisplayName("map(Forbidden) → RerouteToError with a generic message; reason not leaked (R018)")
  void map_forbidden() throws Exception {
    Object result = invokeMap(new AuthorizationDecision.Forbidden("denied: subject=alice policy=secret"));
    assertInstanceOf(AccessDecision.RerouteToError.class, result);
    AccessDecision.RerouteToError err = (AccessDecision.RerouteToError) result;
    assertEquals(SecurityException.class, err.type());
    assertEquals("Access denied", err.message());
    assertFalse(err.message().contains("alice"),
        "the internal reason must never reach the user-facing error view");
  }

  @Test
  @DisplayName("map(StepUpRequired) → AccessDecision.Reroute to the default 'step-up' route")
  void map_stepUpDefaultRoute() throws Exception {
    com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver.resetAll();
    try {
      Object result = invokeMap(new AuthorizationDecision.StepUpRequired("needs mfa", "MFA"));
      AccessDecision.Reroute reroute = (AccessDecision.Reroute) result;
      assertEquals("step-up", reroute.target());
      assertEquals(false, reroute.asForward());
    } finally {
      com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver.resetAll();
    }
  }

  @Test
  @DisplayName("map(StepUpRequired) honours the configured stepUpRouteName")
  void map_stepUpConfiguredRoute() throws Exception {
    com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver.resetAll();
    com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver
        .setStepUpRouteName("mfa-challenge");
    try {
      Object result = invokeMap(new AuthorizationDecision.StepUpRequired("needs mfa", "MFA"));
      AccessDecision.Reroute reroute = (AccessDecision.Reroute) result;
      assertEquals("mfa-challenge", reroute.target());
    } finally {
      com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver.resetAll();
    }
  }

  @Test
  @DisplayName("map(Unauthenticated) honours the configured loginRouteName (R025)")
  void map_unauthenticatedConfiguredRoute() throws Exception {
    com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver.resetAll();
    com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver
        .setLoginRouteName("sign-in");
    try {
      Object result = invokeMap(new AuthorizationDecision.Unauthenticated("not signed in"));
      AccessDecision.Reroute reroute = (AccessDecision.Reroute) result;
      assertEquals("sign-in", reroute.target(),
          "Unauthenticated must reroute to the configured login route, not a hardcoded literal");
      assertEquals(false, reroute.asForward());
    } finally {
      com.svenruppert.jsentinel.authorization.api.JSentinelServiceResolver.resetAll();
    }
  }

  // ── Helpers ───────────────────────────────────────────────────

  private Object invokeEvaluate(Object evaluator, AccessContext context, Annotation annotation)
      throws ReflectiveOperationException {
    Method m = AuthorizationListener.class.getDeclaredMethod(
        "evaluate", Object.class, AccessContext.class, Annotation.class);
    m.setAccessible(true);
    try {
      return m.invoke(listener, evaluator, context, annotation);
    } catch (InvocationTargetException ite) {
      throw ite;
    }
  }

  private Object invokeMap(AuthorizationDecision decision) throws ReflectiveOperationException {
    Method m = AuthorizationListener.class.getDeclaredMethod("map", AuthorizationDecision.class);
    m.setAccessible(true);
    return m.invoke(listener, decision);
  }

  private static AccessContext ctx() {
    return new AccessContext(
        Optional.empty(), "vaadin-view", "Test", "navigate", Map.of());
  }

  private static Annotation markerAnnotation() {
    // Use a real annotation instance — Deprecated has a runtime annotation we can pull from this class.
    java.lang.annotation.Annotation[] anns = AnnotatedFixture.class.getAnnotations();
    if (anns.length == 0) fail("AnnotatedFixture must carry at least one runtime annotation");
    return anns[0];
  }

  @Deprecated
  private static final class AnnotatedFixture {
  }
}
