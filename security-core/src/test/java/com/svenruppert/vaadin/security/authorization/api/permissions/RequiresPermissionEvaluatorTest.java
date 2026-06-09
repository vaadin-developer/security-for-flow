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
package com.svenruppert.vaadin.security.authorization.api.permissions;

import com.svenruppert.vaadin.security.authorization.annotations.RequiresPermission;
import com.svenruppert.vaadin.security.authorization.api.AuthorizationDecision;
import com.svenruppert.vaadin.security.authorization.api.JSentinelSubject;
import com.svenruppert.vaadin.security.authorization.navigation.AccessContext;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

@DisplayName("RequiresPermissionEvaluator")
class RequiresPermissionEvaluatorTest {

  private final RequiresPermissionEvaluator evaluator = new RequiresPermissionEvaluator();

  @Test
  @DisplayName("missing subject is unauthenticated")
  void missingSubject() throws NoSuchMethodException {
    AuthorizationDecision decision = evaluator.evaluate(
        context(Optional.empty()),
        annotation("read"));

    assertInstanceOf(AuthorizationDecision.Unauthenticated.class, decision);
  }

  @Test
  @DisplayName("matching permission grants access")
  void matchingPermission() throws NoSuchMethodException {
    JSentinelSubject subject = new JSentinelSubject(
        "u1", "User", Set.of(), Set.of(new PermissionName("document:read")));

    AuthorizationDecision decision = evaluator.evaluate(
        context(Optional.of(subject)),
        annotation("read"));

    assertInstanceOf(AuthorizationDecision.Granted.class, decision);
  }

  @Test
  @DisplayName("missing permission forbids access")
  void missingPermission() throws NoSuchMethodException {
    JSentinelSubject subject = new JSentinelSubject("u1", "User", Set.of(), Set.of());

    AuthorizationDecision decision = evaluator.evaluate(
        context(Optional.of(subject)),
        annotation("delete"));

    assertInstanceOf(AuthorizationDecision.Forbidden.class, decision);
  }

  private static AccessContext context(Optional<JSentinelSubject> subject) {
    return new AccessContext(subject, "rest-endpoint", "/documents", "read", Map.of());
  }

  private static RequiresPermission annotation(String methodName) throws NoSuchMethodException {
    Method method = Fixtures.class.getDeclaredMethod(methodName);
    return method.getAnnotation(RequiresPermission.class);
  }

  static class Fixtures {
    @RequiresPermission("document:read")
    void read() {
    }

    @RequiresPermission("document:delete")
    void delete() {
    }
  }
}
