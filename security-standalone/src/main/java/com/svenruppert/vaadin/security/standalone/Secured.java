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

import com.svenruppert.vaadin.security.authorization.api.AccessEvaluator;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationEvaluator;
import com.svenruppert.vaadin.security.authorization.api.SecuritySubject;
import com.svenruppert.vaadin.security.authorization.api.AccessDeniedException;
import com.svenruppert.vaadin.security.authorization.api.SecurityServiceResolver;
import com.svenruppert.vaadin.security.authorization.api.SubjectStores;
import com.svenruppert.vaadin.security.authorization.api.permissions.HasPermissions;
import com.svenruppert.vaadin.security.authorization.api.roles.HasRoles;
import com.svenruppert.vaadin.security.authorization.impl.AnnotationAccessEvaluatorPair;
import com.svenruppert.vaadin.security.authorization.impl.SecurityAnnotationScanner;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import com.svenruppert.vaadin.security.authorization.navigation.AccessDecision;

import java.lang.annotation.Annotation;
import java.lang.reflect.Proxy;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Builds a dynamic-proxy wrapper around any interface so that every
 * invocation goes through {@link SecurityAnnotationScanner} and, if the
 * method (or its declaring class) carries a security annotation, runs
 * the matching evaluator before delegating to the real implementation.
 * <p>
 * Reject is signalled by throwing {@link AccessDeniedException}. Grants
 * fall through to the delegate; reroute / error decisions are mapped to
 * the same {@code AccessDeniedException} since standalone applications
 * have no navigation concept.
 *
 * <p>Subject resolution: the proxy reads the current subject through the
 * application's {@link com.svenruppert.vaadin.security.authentication.AuthenticationService}
 * + {@link com.svenruppert.vaadin.security.authorization.api.SubjectStore},
 * and assembles a {@link SecuritySubject} on the fly via the configured
 * {@link com.svenruppert.vaadin.security.authorization.api.AuthorizationService}.
 * Applications that already have a {@code SecuritySubject} (e.g. from a
 * custom auth path) can register it manually as the subject.
 *
 * <p>Usage:
 * <pre>
 * MyService secured = Secured.wrap(MyService.class, new MyServiceImpl());
 * secured.deleteDocument(id);  // throws AccessDeniedException if not allowed
 * </pre>
 */
public final class Secured {

  private static final SecurityAnnotationScanner SCANNER = new SecurityAnnotationScanner();

  private Secured() {
  }

  /**
   * Wraps {@code delegate} in a dynamic proxy that enforces the security
   * annotations declared on {@code interfaceType} (class-level or per
   * method).
   *
   * @param interfaceType the interface the proxy implements
   * @param delegate      the real implementation
   * @param <T>           the interface type
   * @return a proxy implementing {@code interfaceType}
   */
  @SuppressWarnings("unchecked")
  public static <T> T wrap(Class<T> interfaceType, T delegate) {
    if (!interfaceType.isInterface()) {
      throw new IllegalArgumentException(
          "Secured.wrap requires an interface; got: " + interfaceType.getName());
    }
    return (T) Proxy.newProxyInstance(
        interfaceType.getClassLoader(),
        new Class<?>[]{interfaceType},
        (proxy, method, args) -> {
          if (method.getDeclaringClass() == Object.class) {
            return method.invoke(delegate, args);
          }
          enforce(method, interfaceType);
          try {
            return method.invoke(delegate, args);
          } catch (java.lang.reflect.InvocationTargetException ite) {
            throw ite.getCause();
          }
        });
  }

  /**
   * Single-shot check on the calling method. Useful when an interface
   * isn't a clean fit (callbacks, lambdas) but the application still
   * wants to enforce {@code @RequiresPermission} / {@code @RequiresRole}
   * declaratively.
   *
   * <p>Pass {@code MyClass.class} and a method name; the scanner picks
   * up class-level or method-level annotations and throws on a denied
   * decision.
   *
   * @param ownerClass  the class declaring the method
   * @param methodName  the method name (overloads ignored — first match)
   * @throws AccessDeniedException if the evaluator rejects the call
   */
  public static void requireAllowed(Class<?> ownerClass, String methodName) {
    java.lang.reflect.Method method = java.util.Arrays.stream(ownerClass.getDeclaredMethods())
        .filter(m -> m.getName().equals(methodName))
        .findFirst()
        .orElseThrow(() -> new IllegalArgumentException(
            "No method named '" + methodName + "' on " + ownerClass.getName()));
    enforce(method, ownerClass);
  }

  private static void enforce(java.lang.reflect.Method method, Class<?> declaring) {
    Optional<AnnotationAccessEvaluatorPair<Annotation>> match = SCANNER.scan(method)
        .or(() -> SCANNER.scan(declaring));
    if (match.isEmpty()) {
      return; // unannotated → no enforcement
    }
    AnnotationAccessEvaluatorPair<Annotation> pair = match.get();
    AccessContext context = new AccessContext(
        currentSecuritySubject(),
        "standalone-method",
        declaring.getSimpleName(),
        method.getName(),
        Map.of());

    Object evaluator = instantiate(pair.evaluatorClass());
    AccessDecision decision = run(evaluator, context, pair.annotation());
    switch (decision) {
      case AccessDecision.Granted ignored -> { /* fall through to delegate */ }
      case AccessDecision.Reroute r ->
          throw new AccessDeniedException("Access denied; reroute requested to " + r.target());
      case AccessDecision.RerouteToError err ->
          throw new AccessDeniedException(err.message() == null ? "Access denied" : err.message());
      case AccessDecision.RerouteWithParameter<?> r ->
          throw new AccessDeniedException("Access denied; reroute requested to " + r.target());
      case AccessDecision.RerouteWithParameters<?> r ->
          throw new AccessDeniedException("Access denied; reroute requested to " + r.target());
    }
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private static Optional<SecuritySubject> currentSecuritySubject() {
    Class<?> subjectType = SecurityServiceResolver
        .<Object, Object>authenticationService()
        .subjectType();
    if (subjectType == null) {
      return Optional.empty();
    }
    Class raw = subjectType;
    Optional<Object> raw0 = SubjectStores.subjectStore().currentSubject(raw);
    if (raw0.isEmpty()) {
      return Optional.empty();
    }
    Object user = raw0.get();
    var auth = SecurityServiceResolver.<Object>authorizationService();
    HasRoles roles = auth.rolesFor(user);
    HasPermissions perms = auth.permissionsFor(user);
    return Optional.of(new SecuritySubject(
        user.toString(),
        user.toString(),
        Set.copyOf(roles.roleNames()),
        Set.copyOf(perms.permissionNames())));
  }

  @SuppressWarnings("unchecked")
  private static AccessDecision run(Object evaluator, AccessContext context, Annotation annotation) {
    if (evaluator instanceof AccessEvaluator<?> ae) {
      return ((AccessEvaluator<Annotation>) ae).evaluate(context, annotation);
    }
    if (evaluator instanceof AuthorizationEvaluator<?> aze) {
      AuthorizationDecision decision =
          ((AuthorizationEvaluator<Annotation>) aze).evaluate(context, annotation);
      return switch (decision) {
        case AuthorizationDecision.Granted ignored -> AccessDecision.granted();
        case AuthorizationDecision.Unauthenticated u -> AccessDecision.reroute("login", false);
        case AuthorizationDecision.Forbidden f -> AccessDecision.deniedWithError(
            SecurityException.class, f.reason());
      };
    }
    throw new IllegalStateException(
        "Unsupported evaluator type: " + evaluator.getClass().getName());
  }

  private static Object instantiate(Class<?> evaluatorClass) {
    try {
      return evaluatorClass.getDeclaredConstructor().newInstance();
    } catch (ReflectiveOperationException e) {
      throw new IllegalStateException(
          "Could not instantiate evaluator " + evaluatorClass.getName(), e);
    }
  }
}
