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
package eu.jsentinel.jcustos.authorization.api.permissions;

import eu.jsentinel.jcustos.authorization.annotations.RequiresAnyPermission;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JCustosSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class RequiresAnyPermissionEvaluatorTest {

  private static AccessContext ctxWithSubject(JCustosSubject subject) {
    return new AccessContext(
        Optional.of(subject), "rest-endpoint", "/x", "read", Map.of());
  }

  private static AccessContext anonymousCtx() {
    return new AccessContext(
        Optional.empty(), "rest-endpoint", "/x", "read", Map.of());
  }

  private static JCustosSubject subjectWith(String... permissions) {
    Set<PermissionName> perms = java.util.Arrays.stream(permissions)
        .map(PermissionName::new)
        .collect(java.util.stream.Collectors.toUnmodifiableSet());
    return new JCustosSubject("u-1", "u-1", Set.of(), perms);
  }

  private static RequiresAnyPermission annotationFor(String... values) {
    return new RequiresAnyPermission() {
      @Override public Class<? extends Annotation> annotationType() { return RequiresAnyPermission.class; }
      @Override public String[] value() { return values; }
    };
  }

  @Test
  @DisplayName("anonymous subject yields Unauthenticated")
  void anonymousUnauthenticated() {
    AuthorizationDecision decision = new RequiresAnyPermissionEvaluator()
        .evaluate(anonymousCtx(), annotationFor("a", "b"));
    assertInstanceOf(AuthorizationDecision.Unauthenticated.class, decision);
  }

  @Test
  @DisplayName("any one matching permission yields Granted")
  void anyOneMatchGrants() {
    AuthorizationDecision decision = new RequiresAnyPermissionEvaluator()
        .evaluate(ctxWithSubject(subjectWith("b")), annotationFor("a", "b", "c"));
    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }

  @Test
  @DisplayName("no matching permission yields Forbidden")
  void noMatchForbidden() {
    AuthorizationDecision decision = new RequiresAnyPermissionEvaluator()
        .evaluate(ctxWithSubject(subjectWith("x", "y")), annotationFor("a", "b"));
    AuthorizationDecision.Forbidden forbidden =
        assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
    assertEquals("Missing any required permission", forbidden.reason());
  }

  @Test
  @DisplayName("empty annotation value yields Forbidden (mis-configured)")
  void emptyValueForbids() {
    AuthorizationDecision decision = new RequiresAnyPermissionEvaluator()
        .evaluate(ctxWithSubject(subjectWith("a")), annotationFor());
    AuthorizationDecision.Forbidden forbidden =
        assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
    assertEquals(
        "@RequiresAnyPermission requires at least one permission",
        forbidden.reason());
  }

  @Test
  @DisplayName("wildcard permission grants via PermissionMatcher")
  void wildcardMatchGrants() {
    AuthorizationDecision decision = new RequiresAnyPermissionEvaluator()
        .evaluate(ctxWithSubject(subjectWith("doc:*")), annotationFor("audit:read", "doc:write"));
    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }
}
