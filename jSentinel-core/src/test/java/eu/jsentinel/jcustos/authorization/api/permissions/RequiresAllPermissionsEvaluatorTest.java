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

import eu.jsentinel.jcustos.authorization.annotations.RequiresAllPermissions;
import eu.jsentinel.jcustos.authorization.api.AuthorizationDecision;
import eu.jsentinel.jcustos.authorization.api.JSentinelSubject;
import eu.jsentinel.jcustos.authorization.navigation.AccessContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.annotation.Annotation;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class RequiresAllPermissionsEvaluatorTest {

  private static AccessContext ctxWithSubject(JSentinelSubject subject) {
    return new AccessContext(
        Optional.of(subject), "rest-endpoint", "/x", "read", Map.of());
  }

  private static AccessContext anonymousCtx() {
    return new AccessContext(
        Optional.empty(), "rest-endpoint", "/x", "read", Map.of());
  }

  private static JSentinelSubject subjectWith(String... permissions) {
    Set<PermissionName> perms = java.util.Arrays.stream(permissions)
        .map(PermissionName::new)
        .collect(java.util.stream.Collectors.toUnmodifiableSet());
    return new JSentinelSubject("u-1", "u-1", Set.of(), perms);
  }

  private static RequiresAllPermissions annotationFor(String... values) {
    return new RequiresAllPermissions() {
      @Override public Class<? extends Annotation> annotationType() { return RequiresAllPermissions.class; }
      @Override public String[] value() { return values; }
    };
  }

  @Test
  @DisplayName("anonymous subject yields Unauthenticated")
  void anonymousUnauthenticated() {
    AuthorizationDecision decision = new RequiresAllPermissionsEvaluator()
        .evaluate(anonymousCtx(), annotationFor("a", "b"));
    assertInstanceOf(AuthorizationDecision.Unauthenticated.class, decision);
  }

  @Test
  @DisplayName("subject holding every listed permission yields Granted")
  void allMatchGrants() {
    AuthorizationDecision decision = new RequiresAllPermissionsEvaluator()
        .evaluate(ctxWithSubject(subjectWith("a", "b", "c")), annotationFor("a", "b"));
    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }

  @Test
  @DisplayName("subject missing one permission yields Forbidden")
  void partialMatchForbids() {
    AuthorizationDecision decision = new RequiresAllPermissionsEvaluator()
        .evaluate(ctxWithSubject(subjectWith("a")), annotationFor("a", "b"));
    AuthorizationDecision.Forbidden forbidden =
        assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
    assertEquals("Missing required permission", forbidden.reason());
  }

  @Test
  @DisplayName("empty annotation value yields Forbidden (mis-configured)")
  void emptyValueForbids() {
    AuthorizationDecision decision = new RequiresAllPermissionsEvaluator()
        .evaluate(ctxWithSubject(subjectWith("a")), annotationFor());
    AuthorizationDecision.Forbidden forbidden =
        assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
    assertEquals(
        "@RequiresAllPermissions requires at least one permission",
        forbidden.reason());
  }

  @Test
  @DisplayName("wildcard permission covers a required pair")
  void wildcardCoversAll() {
    AuthorizationDecision decision = new RequiresAllPermissionsEvaluator()
        .evaluate(ctxWithSubject(subjectWith("doc:*")), annotationFor("doc:read", "doc:write"));
    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }
}
